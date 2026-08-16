/* ---------------------------------------------------------------------------
   Ark IdP admin console.

   Talks only to the current management API (/api/oauth/v1/...) and links out to
   the current protocol surface (/{tenant}/oauth2/..., /{tenant}/.well-known/...).

   Differences from the v1 console this replaces, beyond the routes:

     * Columns are declared rather than generated with autoColumns. The client
       record grew RFC 7591 registration metadata, and a generated grid renders
       every column of it — including the tenant's rsa_private — as an editable
       text box. Clients are now edited in a form, and private keys are never
       sent back to the server or drawn on screen.
     * Entities that store a JSON list in a string column expose both shapes
       (`scopes` and `scopes_`). Both are written on save, so a payload cannot
       depend on JSON property order to be interpreted correctly.
     * No third-party helper libraries. Tabulator is the single external
       dependency, pinned; the toast and DOM helpers below are ~20 lines.
   --------------------------------------------------------------------------- */
(function () {
    "use strict";

    var root = document.getElementById("ark-admin");
    var APP_ROOT = root.dataset.appRoot || "";
    var TENANT_ID = root.dataset.tenantId || "";
    var API = APP_ROOT + "/api/oauth/v1";

    // ---------------------------------------------------------------- helpers

    function toast(kind, message, ms) {
        var host = document.getElementById("ark-toasts");
        var el = document.createElement("div");
        el.className = "ark-toast ark-toast-" + kind;
        el.textContent = message;
        host.appendChild(el);
        setTimeout(function () { el.remove(); }, ms || 3500);
    }

    function getJson(url) {
        return fetch(url, { headers: { Accept: "application/json" } }).then(function (r) {
            if (!r.ok) throw new Error(r.status + " " + r.statusText);
            return r.json();
        });
    }

    function postJson(url, body) {
        return fetch(url, {
            method: "POST",
            body: JSON.stringify(body),
            headers: { Accept: "application/json", "Content-Type": "application/json" }
        }).then(function (r) {
            if (!r.ok) throw new Error(r.status + " " + r.statusText);
            return r.json();
        });
    }

    // Every management endpoint answers { error, msg, data }. Surface both outcomes the
    // same way so a failed save is never mistaken for a successful one.
    function save(url, body, okMessage) {
        return postJson(url, body).then(function (res) {
            if (res && res.error) {
                toast("f", res.msg || "request failed", 6000);
                return Promise.reject(new Error(res.msg || "request failed"));
            }
            toast("s", okMessage || (res && res.msg) || "saved", 3000);
            return res;
        }).catch(function (err) {
            if (err && err.message && err.message.indexOf("request failed") < 0) {
                toast("f", err.message, 6000);
            }
            throw err;
        });
    }

    function el(html) {
        var t = document.createElement("template");
        t.innerHTML = html.trim();
        return t.content.firstElementChild;
    }

    function lines(value) {
        return (value || "").split("\n").map(function (s) { return s.trim(); }).filter(Boolean);
    }

    /** Writes a JSON-list property in both the shapes the entity exposes. */
    function setList(target, field, values) {
        target[field] = values;
        target[field + "_"] = JSON.stringify(values);
    }

    function listOf(record, field) {
        var v = record ? record[field] : null;
        if (Array.isArray(v)) return v;
        var raw = record ? record[field + "_"] : null;
        if (!raw) return [];
        try { return JSON.parse(raw) || []; } catch (e) { return []; }
    }

    function checkboxes(container, options, selected) {
        container.innerHTML = "";
        var chosen = selected || [];
        options.forEach(function (opt) {
            var id = container.id + "-" + opt.replace(/[^a-z0-9]+/gi, "_");
            var row = el('<div class="ark-check"><input type="checkbox" id="' + id + '" /><label for="' + id + '"></label></div>');
            var input = row.querySelector("input");
            input.value = opt;
            input.checked = chosen.indexOf(opt) > -1;
            row.querySelector("label").textContent = opt;
            container.appendChild(row);
        });
    }

    function checkedValues(container) {
        return Array.prototype.slice
            .call(container.querySelectorAll("input[type=checkbox]:checked"))
            .map(function (i) { return i.value; });
    }

    var GRANT_TYPES = [
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code"
    ];
    var RESPONSE_TYPES = ["code"];

    // ------------------------------------------------------------------ state

    var state = { tenants: [], clients: [], users: [], claims: [], scopes: [] };
    var tables = {};

    function tenantOptions() {
        return state.tenants.reduce(function (acc, t) {
            acc[t.tenant_id] = t.name || t.tenant_id;
            return acc;
        }, {});
    }

    // ---------------------------------------------------------------- tenants

    function actionColumn(label, cls, handler, width) {
        return {
            title: "",
            field: "__" + label.toLowerCase().replace(/\W+/g, "_"),
            width: width || 80,
            hozAlign: "center",
            headerSort: false,
            formatter: function () {
                return '<button type="button" class="' + (cls || "") + '">' + label + "</button>";
            },
            cellClick: function (e, cell) { handler(cell); }
        };
    }

    function loadTenants() {
        return getJson(API + "/tenant/list").then(function (res) {
            state.tenants = res.data || [];

            if (!tables.tenant) {
                tables.tenant = new Tabulator("#tbl_tenant", {
                    data: state.tenants,
                    layout: "fitColumns",
                    columns: [
                        { title: "tenant_id", field: "tenant_id", editor: "input", widthGrow: 2 },
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        { title: "display", field: "display", editor: "input", widthGrow: 2 },
                        { title: "issuer (v1)", field: "issuer", editor: "input", widthGrow: 3 },
                        { title: "audience (v1)", field: "audience", editor: "input", widthGrow: 3 },
                        { title: "expire_mins", field: "expire_mins", editor: "number", width: 110 },
                        {
                            title: "key", field: "rsa_public", width: 80, hozAlign: "center", headerSort: false,
                            // The key itself is deliberately not rendered or editable. Rotation is a
                            // two-phase operation against the signing_keys table, not a text edit.
                            formatter: function (cell) {
                                return cell.getValue()
                                    ? '<span class="ark-badge ark-badge-ok">present</span>'
                                    : '<span class="ark-badge ark-badge-warn">on save</span>';
                            }
                        },
                        actionColumn("Save", "", function (cell) {
                            var row = Object.assign({}, cell.getRow().getData());
                            // Never send the key material back. The server keeps the stored pair
                            // when it is absent, and mints one for a tenant that has none.
                            delete row.rsa_private;
                            delete row.rsa_public;
                            save(API + "/tenant/upsert", row, "tenant saved").then(loadTenants).catch(function () { });
                        }),
                        {
                            title: "", width: 90, hozAlign: "center", headerSort: false,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                if (!d.tenant_id) return "";
                                return '<a href="' + APP_ROOT + "/" + encodeURIComponent(d.tenant_id) +
                                    '/.well-known/openid-configuration" target="_blank" rel="noopener">discovery</a>';
                            }
                        }
                    ]
                });
            } else {
                tables.tenant.setData(state.tenants);
            }

            var sel = document.getElementById("sel-tenant");
            var current = sel.value;
            sel.innerHTML = "";
            sel.add(new Option("Select tenant", ""));
            state.tenants.forEach(function (t) { sel.add(new Option(t.name || t.tenant_id, t.tenant_id)); });
            sel.value = current || TENANT_ID;
        });
    }

    // ----------------------------------------------------------------- scopes

    function loadScopes() {
        return getJson(API + "/scope/list").then(function (res) {
            state.scopes = res.data || [];

            if (!tables.scope) {
                tables.scope = new Tabulator("#tbl_scope", {
                    data: state.scopes,
                    layout: "fitColumns",
                    columns: [
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        { title: "display", field: "display", editor: "input", widthGrow: 2 },
                        { title: "description", field: "description", editor: "input", widthGrow: 3 },
                        {
                            // Edited as a comma separated list; normalised back to an array on save,
                            // so the cell holds a string between the edit and the save.
                            title: "claims unlocked", field: "claims", editor: "input", widthGrow: 3,
                            formatter: function (cell) {
                                var v = cell.getValue();
                                return Array.isArray(v) ? v.join(", ") : (v || "");
                            }
                        },
                        { title: "default", field: "is_default", editor: "tickCross", formatter: "tickCross", width: 90 },
                        { title: "consent", field: "require_consent", editor: "tickCross", formatter: "tickCross", width: 90 },
                        { title: "protocol", field: "is_protocol", formatter: "tickCross", width: 90 },
                        actionColumn("Save", "", function (cell) {
                            var row = Object.assign({}, cell.getRow().getData());
                            var claims = row.claims;
                            if (!Array.isArray(claims)) {
                                claims = (claims || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
                            }
                            setList(row, "claims", claims);
                            save(API + "/scope/upsert", row, "scope saved")
                                .then(loadScopes).then(refreshScopePickers).catch(function () { });
                        }),
                        actionColumn("Delete", "ark-btn-danger", function (cell) {
                            var row = cell.getRow().getData();
                            if (!row.name) { cell.getRow().delete(); return; }
                            if (!confirm("Delete scope '" + row.name + "'?")) return;
                            save(API + "/scope/delete", row, "scope deleted")
                                .then(loadScopes).then(refreshScopePickers).catch(function () { });
                        })
                    ]
                });
            } else {
                tables.scope.setData(state.scopes);
            }
        });
    }

    function refreshScopePickers() {
        var box = document.getElementById("cl-scopes");
        if (box.dataset.clientOpen === "true") {
            var selected = checkedValues(box);
            checkboxes(box, state.scopes.map(function (s) { return s.name; }), selected);
        }
    }

    // ---------------------------------------------------------------- clients

    function loadClients() {
        return getJson(API + "/client/list").then(function (res) {
            state.clients = res.data || [];

            if (!tables.client) {
                tables.client = new Tabulator("#tbl_client", {
                    data: state.clients,
                    layout: "fitColumns",
                    columns: [
                        { title: "tenant", field: "tenant_id", widthGrow: 1 },
                        { title: "client_id", field: "client_id", widthGrow: 2 },
                        {
                            title: "name", field: "client_name", widthGrow: 2,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                return d.client_name || d.display || d.name || "";
                            }
                        },
                        { title: "type", field: "application_type", width: 90 },
                        {
                            title: "auth", field: "token_endpoint_auth_method", width: 165,
                            formatter: function (cell) {
                                var v = cell.getValue() || "";
                                var cls = v === "none" ? "ark-badge-warn" : "ark-badge-off";
                                return '<span class="ark-badge ' + cls + '">' + (v === "none" ? "public" : v) + "</span>";
                            }
                        },
                        {
                            title: "active", field: "is_active", width: 80, hozAlign: "center",
                            formatter: function (cell) {
                                return cell.getValue()
                                    ? '<span class="ark-badge ark-badge-ok">yes</span>'
                                    : '<span class="ark-badge ark-badge-off">no</span>';
                            }
                        },
                        actionColumn("Edit", "", function (cell) { openClient(cell.getRow().getData()); }),
                        {
                            title: "", width: 90, hozAlign: "center", headerSort: false,
                            formatter: function (cell) {
                                var d = cell.getRow().getData();
                                if (!d.client_id || !d.tenant_id) return "";
                                return '<a href="' + integrateUrl(d) + '" target="_blank" rel="noopener">setup</a>';
                            }
                        }
                    ]
                });
            } else {
                tables.client.setData(state.clients);
            }
        });
    }

    function integrateUrl(client) {
        return APP_ROOT + "/" + encodeURIComponent(client.tenant_id) +
            "/oauth2/integrate/" + encodeURIComponent(client.client_id);
    }

    // ------------------------------------------------------------ client form

    var drawer = document.getElementById("client-drawer");
    var backdrop = document.getElementById("client-drawer-backdrop");
    var editing = null;

    function field(id) { return document.getElementById("cl-" + id); }

    var TEXT_FIELDS = [
        "client_id", "client_name", "display", "name", "domain", "client_logo",
        "client_uri", "policy_uri", "tos_uri", "jwks_uri",
        "redirect_url", "logout_url", "redirect_relative"
    ];
    var NUMBER_FIELDS = [
        "access_token_lifetime_seconds", "id_token_lifetime_seconds",
        "refresh_token_lifetime_seconds", "authorization_code_lifetime_seconds", "expire_mins"
    ];
    var FLAG_FIELDS = ["is_active", "require_pkce", "require_par", "require_consent", "refresh_token_rotation"];

    function openClient(client) {
        editing = client ? Object.assign({}, client) : {
            application_type: "web",
            token_endpoint_auth_method: "client_secret_basic",
            is_active: true,
            require_pkce: true,
            refresh_token_rotation: true,
            access_token_lifetime_seconds: 3600,
            id_token_lifetime_seconds: 3600,
            refresh_token_lifetime_seconds: 1209600,
            authorization_code_lifetime_seconds: 60,
            expire_mins: 480,
            tenant_id: TENANT_ID
        };

        document.getElementById("client-drawer-title").textContent =
            editing.id ? (editing.client_id || "Client") : "New client";

        var tenantSelect = field("tenant_id");
        tenantSelect.innerHTML = "";
        state.tenants.forEach(function (t) { tenantSelect.add(new Option(t.name || t.tenant_id, t.tenant_id)); });
        tenantSelect.value = editing.tenant_id || TENANT_ID;

        TEXT_FIELDS.forEach(function (f) { field(f).value = editing[f] || ""; });
        NUMBER_FIELDS.forEach(function (f) { field(f).value = editing[f] != null ? editing[f] : ""; });
        FLAG_FIELDS.forEach(function (f) { field(f).checked = !!editing[f]; });
        field("application_type").value = editing.application_type || "web";
        field("token_endpoint_auth_method").value = editing.token_endpoint_auth_method || "client_secret_basic";

        field("redirect_uris").value = listOf(editing, "redirect_uris").join("\n");
        field("post_logout_redirect_uris").value = listOf(editing, "post_logout_redirect_uris").join("\n");
        field("contacts").value = listOf(editing, "contacts").join("\n");

        var grants = listOf(editing, "grant_types");
        checkboxes(field("grant_types"), GRANT_TYPES, grants.length ? grants : ["authorization_code", "refresh_token"]);
        var responses = listOf(editing, "response_types");
        checkboxes(field("response_types"), RESPONSE_TYPES, responses.length ? responses : ["code"]);
        var scopes = listOf(editing, "scopes");
        var box = field("scopes");
        box.dataset.clientOpen = "true";
        checkboxes(box, state.scopes.map(function (s) { return s.name; }),
            scopes.length ? scopes : ["openid", "profile", "email", "offline_access"]);

        document.getElementById("cl-secret-state").textContent = editing.client_secret_hash
            ? "A secret is set. Regenerating replaces it immediately."
            : "No secret set.";
        var out = document.getElementById("cl-secret-value");
        out.hidden = true;
        out.innerHTML = "";
        document.getElementById("cl-secret-reset").disabled = !editing.id;
        document.getElementById("client-delete").disabled = !editing.id;
        document.getElementById("client-integrate").disabled = !editing.id;

        drawer.dataset.open = "true";
        backdrop.dataset.open = "true";
    }

    function closeClient() {
        drawer.dataset.open = "false";
        backdrop.dataset.open = "false";
        field("scopes").dataset.clientOpen = "false";
        editing = null;
    }

    function readClientForm() {
        var out = Object.assign({}, editing);
        out.tenant_id = field("tenant_id").value;
        TEXT_FIELDS.forEach(function (f) { out[f] = field(f).value.trim() || null; });
        NUMBER_FIELDS.forEach(function (f) {
            var raw = field(f).value;
            if (raw !== "") out[f] = parseInt(raw, 10);
        });
        FLAG_FIELDS.forEach(function (f) { out[f] = field(f).checked; });
        out.application_type = field("application_type").value;
        out.token_endpoint_auth_method = field("token_endpoint_auth_method").value;

        setList(out, "redirect_uris", lines(field("redirect_uris").value));
        setList(out, "post_logout_redirect_uris", lines(field("post_logout_redirect_uris").value));
        setList(out, "contacts", lines(field("contacts").value));
        setList(out, "grant_types", checkedValues(field("grant_types")));
        setList(out, "response_types", checkedValues(field("response_types")));
        setList(out, "scopes", checkedValues(field("scopes")));

        // Navigation properties are not part of the payload; sending a populated `tenant`
        // makes the change tracker try to insert the tenant again.
        delete out.tenant;
        return out;
    }

    document.getElementById("client-add").addEventListener("click", function () { openClient(null); });
    document.getElementById("client-drawer-close").addEventListener("click", closeClient);
    backdrop.addEventListener("click", closeClient);
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && drawer.dataset.open === "true") closeClient();
    });

    document.getElementById("client-save").addEventListener("click", function () {
        var payload = readClientForm();
        if (!payload.client_id) { toast("w", "client_id is required", 4000); return; }
        if (!payload.tenant_id) { toast("w", "a tenant is required", 4000); return; }
        save(API + "/client/upsert", payload, "client saved").then(function (res) {
            editing = res.data || payload;
            return loadClients();
        }).then(function () {
            // Pick the saved record back up so the drawer holds the server's id.
            var match = state.clients.filter(function (c) {
                return c.tenant_id === payload.tenant_id && c.client_id === payload.client_id;
            })[0];
            if (match) openClient(match);
        }).catch(function () { });
    });

    document.getElementById("client-delete").addEventListener("click", function () {
        if (!editing || !editing.id) return;
        if (!confirm("Delete client '" + editing.client_id + "'? Applications using it will stop being able to sign in.")) return;
        save(API + "/client/delete", { id: editing.id, client_id: editing.client_id, tenant_id: editing.tenant_id }, "client deleted")
            .then(function () { closeClient(); return loadClients(); })
            .catch(function () { });
    });

    document.getElementById("client-integrate").addEventListener("click", function () {
        if (!editing || !editing.client_id) return;
        window.open(integrateUrl(editing), "_blank", "noopener");
    });

    document.getElementById("cl-secret-reset").addEventListener("click", function () {
        if (!editing || !editing.client_id) return;
        if (!confirm("Regenerate the secret for '" + editing.client_id + "'? The current one stops working immediately.")) return;
        save(API + "/client/secret/reset", { client_id: editing.client_id, tenant_id: editing.tenant_id })
            .then(function (res) {
                var out = document.getElementById("cl-secret-value");
                out.hidden = false;
                out.innerHTML = "";
                out.appendChild(el('<div class="ark-field"><label>client_secret (shown once)</label></div>'));
                var input = document.createElement("input");
                input.type = "text";
                input.readOnly = true;
                input.value = res.data.client_secret;
                input.addEventListener("focus", function () { input.select(); });
                out.appendChild(input);
                document.getElementById("cl-secret-state").textContent = "A secret is set. Regenerating replaces it immediately.";
                return loadClients();
            })
            .catch(function () { });
    });

    document.getElementById("cl-logo-pick").addEventListener("click", function () {
        document.getElementById("cl-logo-file").click();
    });
    document.getElementById("cl-logo-file").addEventListener("change", function (e) {
        var file = e.target.files && e.target.files[0];
        if (!file) return;
        if (file.size > 256 * 1024) { toast("w", "image is larger than 256 KB — link to it instead", 5000); return; }
        var reader = new FileReader();
        reader.onload = function (ev) { field("client_logo").value = ev.target.result; };
        reader.readAsDataURL(file);
    });

    // ------------------------------------------------------------------ users

    function loadUsers() {
        return getJson(API + "/user/list").then(function (res) {
            state.users = res.data || [];

            if (!tables.user) {
                tables.user = new Tabulator("#tbl_user", {
                    data: state.users,
                    layout: "fitColumns",
                    columns: [
                        { title: "email", field: "email", editor: "input", widthGrow: 3 },
                        { title: "name", field: "name", editor: "input", widthGrow: 2 },
                        {
                            title: "type", field: "type", editor: "list", width: 110,
                            editorParams: { values: ["user", "service"] }
                        },
                        { title: "reset_mode", field: "reset_mode", editor: "tickCross", formatter: "tickCross", width: 110 },
                        { title: "emailed", field: "emailed", formatter: "tickCross", width: 95 },
                        { title: "ref_uid", field: "ref_uid", widthGrow: 2 },
                        { title: "at", field: "at", width: 165 },
                        actionColumn("Save", "", function (cell) {
                            var row = cell.getRow().getData();
                            if (!row.email) { toast("w", "email is required", 4000); return; }
                            save(API + "/user/upsert", row, "user saved").then(loadUsers).catch(function () { });
                        }),
                        actionColumn("Reset password", "", function (cell) {
                            var row = cell.getRow().getData();
                            if (!row.email) return;
                            save(API + "/user/pw/reset/init", row).then(loadUsers).catch(function () { });
                        }, 150)
                    ]
                });
            } else {
                tables.user.setData(state.users);
            }

            var sel = document.getElementById("sel-user");
            var current = sel.value;
            sel.innerHTML = "";
            sel.add(new Option("Select user", ""));
            state.users.forEach(function (u) { sel.add(new Option(u.name ? u.name + " — " + u.email : u.email, u.email)); });
            sel.value = current;
        });
    }

    // ----------------------------------------------------------------- claims

    function loadClaims() {
        return getJson(API + "/claim/list").then(function (res) {
            state.claims = res.data || [];
            renderClaims();
        });
    }

    function renderClaims() {
        var host = document.getElementById("claim-list");
        host.innerHTML = "";
        state.claims.forEach(function (claim) {
            var tag = el('<span class="tag" draggable="true"><span></span><button type="button" title="Delete claim">&times;</button></span>');
            tag.querySelector("span").textContent = claim.key;
            tag.addEventListener("dragstart", function (e) {
                e.dataTransfer.setData("text/plain", claim.key);
                e.dataTransfer.effectAllowed = "copy";
            });
            tag.querySelector("button").addEventListener("click", function () {
                if (!confirm("Delete claim '" + claim.key + "' from the catalogue?")) return;
                save(API + "/claim/delete", claim, "claim deleted").then(loadClaims).catch(function () { });
            });
            host.appendChild(tag);
        });
    }

    document.getElementById("claim-new").addEventListener("keypress", function (e) {
        if (e.key !== "Enter") return;
        var value = e.target.value.trim();
        if (!value) return;
        if (state.claims.some(function (c) { return c.key === value; })) {
            toast("w", "'" + value + "' is already in the catalogue", 3000);
            return;
        }
        save(API + "/claim/upsert", { key: value, display: value }, "claim added")
            .then(function () { e.target.value = ""; return loadClaims(); })
            .catch(function () { });
    });

    // ---------------------------------------------------------- access mapping

    function clientOptionsFor(tenantId) {
        // ArkUserClientClaim.client_id holds the client's surrogate id, not its client_id
        // string — that is what the token endpoint joins on when it resolves ark_claims.
        return state.clients
            .filter(function (c) { return c.tenant_id === tenantId; })
            .reduce(function (acc, c) {
                acc[c.id] = (c.client_name || c.display || c.client_id) + " (" + c.client_id + ")";
                return acc;
            }, {});
    }

    function claimsCell(cell) {
        var row = cell.getRow();
        var values = cell.getValue() || [];
        var box = el('<div class="ark-drop-cell"></div>');

        function redraw() {
            box.innerHTML = "";
            if (!values.length) box.appendChild(el('<span class="ark-drop-empty">drop claims here</span>'));
            values.forEach(function (claim, index) {
                var tag = el('<span class="tag"><span></span><button type="button">&times;</button></span>');
                tag.querySelector("span").textContent = claim;
                tag.querySelector("button").addEventListener("click", function () {
                    values.splice(index, 1);
                    row.update({ claims: values });
                    redraw();
                });
                box.appendChild(tag);
            });
        }

        box.addEventListener("dragover", function (e) { e.preventDefault(); box.classList.add("ark-drop-over"); });
        box.addEventListener("dragleave", function () { box.classList.remove("ark-drop-over"); });
        box.addEventListener("drop", function (e) {
            e.preventDefault();
            box.classList.remove("ark-drop-over");
            var claim = e.dataTransfer.getData("text/plain");
            if (!claim || values.indexOf(claim) > -1) return;
            values.push(claim);
            row.update({ claims: values });
            redraw();
        });

        redraw();
        return box;
    }

    function loadMapping() {
        var email = document.getElementById("sel-user").value;
        var tenantId = document.getElementById("sel-tenant").value;

        var build = function (data) {
            if (tables.mapping) {
                tables.mapping.setData(data);
                return;
            }
            tables.mapping = new Tabulator("#tbl_mapping", {
                data: data,
                height: "320px",
                layout: "fitColumns",
                columns: [
                    { title: "email", field: "email", widthGrow: 2 },
                    { title: "tenant", field: "tenant_id", widthGrow: 1 },
                    {
                        title: "client", field: "client_id", editor: "list", widthGrow: 2,
                        editorParams: function () {
                            return { values: clientOptionsFor(document.getElementById("sel-tenant").value) };
                        },
                        formatter: function (cell) {
                            var options = clientOptionsFor(cell.getRow().getData().tenant_id);
                            return options[cell.getValue()] || cell.getValue() || "";
                        }
                    },
                    { title: "claims", field: "claims", widthGrow: 3, formatter: claimsCell },
                    actionColumn("Save", "", function (cell) {
                        var row = Object.assign({}, cell.getRow().getData());
                        if (!row.client_id) { toast("w", "pick a client first", 4000); return; }
                        setList(row, "claims", row.claims || []);
                        delete row.client;
                        delete row.tenant;
                        save(API + "/user/client/claims/upsert", row, "mapping saved")
                            .then(loadMapping).catch(function () { });
                    }),
                    actionColumn("Delete", "ark-btn-danger", function (cell) {
                        var row = cell.getRow().getData();
                        if (!row.id) { cell.getRow().delete(); return; }
                        save(API + "/user/client/claims/delete", row, "mapping deleted")
                            .then(function () { cell.getRow().delete(); }).catch(function () { });
                    }),
                    {
                        title: "", width: 165, hozAlign: "center", headerSort: false,
                        // Service accounts hold their long-lived token in place of a password;
                        // this reissues it.
                        formatter: function (cell) {
                            var row = cell.getRow().getData();
                            var isService = (row.claims || []).indexOf("service_role") > -1;
                            return isService ? '<button type="button" class="ark-btn-ghost">Regenerate token</button>' : "";
                        },
                        cellClick: function (e, cell) {
                            var row = cell.getRow().getData();
                            if ((row.claims || []).indexOf("service_role") < 0) return;
                            save(API + "/service/pw/reset", row).catch(function () { });
                        }
                    }
                ]
            });
        };

        if (!email || !tenantId) { build([]); return Promise.resolve(); }
        return getJson(API + "/user/list/client/claims/mapping/" +
            encodeURIComponent(email) + "/" + encodeURIComponent(tenantId))
            .then(function (res) { build(res.data || []); });
    }

    document.getElementById("sel-user").addEventListener("change", loadMapping);
    document.getElementById("sel-tenant").addEventListener("change", loadMapping);

    document.getElementById("mapping-add").addEventListener("click", function () {
        var email = document.getElementById("sel-user").value;
        var tenantId = document.getElementById("sel-tenant").value;
        if (!email || !tenantId) {
            toast("w", "select both a user and a tenant before adding a mapping", 4000);
            return;
        }
        if (!tables.mapping) { loadMapping().then(function () { tables.mapping.addRow({ email: email, tenant_id: tenantId, claims: [] }); }); return; }
        tables.mapping.addRow({ email: email, tenant_id: tenantId, claims: [] });
    });

    // -------------------------------------------------------------- new rows

    document.getElementById("tenant-add").addEventListener("click", function () {
        tables.tenant.addRow({ expire_mins: 480 });
    });
    document.getElementById("user-add").addEventListener("click", function () {
        tables.user.addRow({ type: "user" });
    });
    document.getElementById("scope-add").addEventListener("click", function () {
        tables.scope.addRow({ claims: [], require_consent: true, is_default: false, is_protocol: false });
    });

    // ----------------------------------------------------------------- start

    Promise.all([loadTenants(), loadScopes(), loadClaims()])
        .then(loadClients)
        .then(loadUsers)
        .then(loadMapping)
        .catch(function (err) {
            toast("f", "could not load the console: " + err.message, 8000);
        });
})();
