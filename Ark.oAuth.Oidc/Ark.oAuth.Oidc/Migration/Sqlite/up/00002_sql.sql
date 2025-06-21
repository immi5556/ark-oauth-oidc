CREATE TABLE if NOT EXISTS "auth_status" (
	"id"	INTEGER NOT NULL,
	"email"	TEXT UNIQUE,
	"retry_count"	INTEGER NOT NULL DEFAULT 0,
	"complex_policy"	INTEGER NOT NULL DEFAULT 0,
	"ip"	TEXT,
	"at"	TEXT,
	CONSTRAINT "PK_ark_status" PRIMARY KEY("id" AUTOINCREMENT)
);