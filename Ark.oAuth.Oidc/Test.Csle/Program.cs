// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;
using ImageMagick;
using TorchSharp;
using YoloSharp;

Console.WriteLine("Hello, World!");


//MagickImage predictImage = new MagickImage(@"C:\Immi\Personal\git_hub\immi5556\ark-oauth-oidc\Ark.oAuth.Oidc\Test.Csle\car_scratch_.jpg");
// MagickImage predictImage = new MagickImage(@"C:\Immi\Personal\git_hub\immi5556\ark-oauth-oidc\Ark.oAuth.Oidc\Test.Csle\0019.JPEG");

// Create predictor
// Predictor predictor = new Predictor(80, yoloType: YoloType.Yolov12, deviceType: DeviceType.CPU, yoloSize: YoloSize.s, dtype: ScalarType.Float32);

// Train model
//predictor.LoadModel(@"C:\Immi\Personal\git_hub\immi5556\ark-oauth-oidc\Ark.oAuth.Oidc\Test.Csle\yolov11s.bin", skipNcNotEqualLayers: true);
//predictor.Train(@"C:\Immi\NTT\Auto-360\car_scratch_images\car_scratch_dataset_2\taini_data_set", valDataPath, outputPath: outputPath, batchSize: batchSize, epochs: epochs, useMosaic: true);
//predictor.Train(@"C:\Immi\NTT\Auto-360\car_scratch_images\car_scratch_dataset_2\taini_data_set_small", batchSize: 24, epochs: 30, numWorkers: 4);

//ImagePredict image
//predictor.LoadModel(Path.Combine(@"C:\Immi\Personal\git_hub\immi5556\ark-oauth-oidc\Ark.oAuth.Oidc\Test.Csle\bin\Debug\net6.0\output", "best.bin"));
// predictor.LoadModel(Path.Combine(@"C:\Immi\Personal\git_hub\immi5556\ark-oauth-oidc\Ark.oAuth.Oidc\Test.Csle", "best.pt"));
//List<Predictor.PredictResult> predictResult = predictor.ImagePredict(predictImage, predictThreshold, iouThreshold);
// List<Predictor.PredictResult> predictResult = predictor.ImagePredict(predictImage);
// Console.WriteLine(predictResult.Count);

bool VerifyPasswordPBKDF2(string password, string savedPasswordHash, int iterations = 100000)
{
    // Extract bytes from saved hash
    byte[] hashBytes = Convert.FromBase64String(savedPasswordHash);

    // Get salt
    byte[] salt = new byte[16];
    Array.Copy(hashBytes, 0, salt, 0, 16);

    // Compute hash of the provided password
    var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
    byte[] hash = pbkdf2.GetBytes(20);

    // Compare hashes
    for (int i = 0; i < 20; i++)
    {
        if (hashBytes[i + 16] != hash[i])
        {
            return false;
        }
    }

    return true;
}


var rr = VerifyPasswordPBKDF2("ntt@123", "oQ/uM0ZQkvs8z/S0KCmarirVZDgeVBB1kRmFO/HMnV/b+16r");