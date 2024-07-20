#ifndef MSAES256FE_SECURE_H
#define MSAES256FE_SECURE_H

#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

#define MSAES256FE_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

class MSAES256_FileEncryption {
public:
    MSAES256_FileEncryption(const wchar_t* file, const std::wstring& key, const std::wstring& operation) :
        file(file), key(key), operation(operation) {}

    void Execute() {
        try {
            if (operation == L"lock") {
                LockFile();
            }
            else if (operation == L"unlock") {
                UnlockFile();
            }
            else {
                std::wcerr << L"ERR: Invalid operation. Please use 'lock' or 'unlock'." << std::endl;
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "ERR: An error occurred: " << ex.what() << std::endl;
        }
    }

private:
    const wchar_t* file;
    std::wstring key;
    std::wstring operation;

    void ShowError(const wchar_t* msg, NTSTATUS status) {
        std::wcerr << L"ERR: " << msg << L" (Code: 0x" << std::hex << status << L")" << std::endl;
    }

    void ValidateStatus(const wchar_t* msg, NTSTATUS status) {
        if (!MSAES256FE_SUCCESS(status)) {
            ShowError(msg, status);
            throw std::runtime_error("ERR: The operation has failed.");
        }
    }

    void AnnounceOperation(const wchar_t* operation) {
        std::wcout << L"MSG: Executing the following operation: " << operation << std::endl;
    }

    void DisplayHex(const void* data, size_t size) {
        const uint8_t* byteData = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < size; ++i) {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(byteData[i]) << L" ";
            if ((i + 1) % 16 == 0) {
                std::wcout << std::endl;
            }
        }
        if (size % 16 != 0) {
            std::wcout << std::endl;
        }
    }

    void GenerateRandomData(std::vector<BYTE>& buffer) {
        AnnounceOperation(L"Generating random data.");
        BCRYPT_ALG_HANDLE randAlgHandle;
        ValidateStatus(L"ERR: The function BCryptOpenAlgorithmProvider has failed.", BCryptOpenAlgorithmProvider(&randAlgHandle, BCRYPT_RNG_ALGORITHM, NULL, 0));
        if (!buffer.empty()) {
            ValidateStatus(L"ERR: The function BCryptGenRandom has failed.", BCryptGenRandom(randAlgHandle, buffer.data(), static_cast<ULONG>(buffer.size()), 0));
        }
        BCryptCloseAlgorithmProvider(randAlgHandle, 0);
        std::wcout << L"MSG: Random data has been generated:" << std::endl;
        DisplayHex(buffer.data(), buffer.size());
    }

    std::vector<BYTE> CreateKey() {
        AnnounceOperation(L"Creating the encryption key.");
        BCRYPT_ALG_HANDLE algHandle;
        ValidateStatus(L"ERR: The function BCryptOpenAlgorithmProvider has failed.", BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0));
        BCRYPT_HASH_HANDLE hashHandle;
        ValidateStatus(L"ERR: The function BCryptCreateHash has failed.", BCryptCreateHash(algHandle, &hashHandle, NULL, 0, NULL, 0, 0));
        ValidateStatus(L"ERR: The function BCryptHashData has failed.", BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(key.c_str())), static_cast<ULONG>(key.size() * sizeof(wchar_t)), 0));
        std::vector<BYTE> keyBuffer(32);
        ValidateStatus(L"ERR: The function BCryptFinishHash has failed.", BCryptFinishHash(hashHandle, keyBuffer.data(), static_cast<ULONG>(keyBuffer.size()), 0));
        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(algHandle, 0);
        std::wcout << L"MSG: The encryption key is:" << std::endl;
        DisplayHex(keyBuffer.data(), keyBuffer.size());
        return keyBuffer;
    }

    std::vector<BYTE> ReadFileContent() {
        std::ifstream fileStream(file, std::ios::binary);
        if (!fileStream.is_open()) {
            throw std::runtime_error("ERR: Unable to open the file for reading.");
        }
        std::vector<BYTE> content((std::istreambuf_iterator<char>(fileStream)), std::istreambuf_iterator<char>());
        return content;
    }

    void WriteFileContent(const std::vector<BYTE>& content, const wchar_t* outputFileName) {
        std::ofstream fileStream(outputFileName, std::ios::binary);
        if (!fileStream.is_open()) {
            throw std::runtime_error("ERR: Unable to open the file for writing.");
        }
        fileStream.write(reinterpret_cast<const char*>(content.data()), content.size());
    }

    void LockFile() {
        AnnounceOperation(L"Locking the file.");
        std::vector<BYTE> fileContent = ReadFileContent();
        std::vector<BYTE> key = CreateKey();
        std::vector<BYTE> iv(16);
        GenerateRandomData(iv);
        std::vector<BYTE> originalIV = iv;
        BCRYPT_ALG_HANDLE encAlgHandle;
        ValidateStatus(L"ERR: The function BCryptOpenAlgorithmProvider has failed.", BCryptOpenAlgorithmProvider(&encAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
        ValidateStatus(L"ERR: The function BCryptSetProperty has failed.", BCryptSetProperty(encAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
        BCRYPT_KEY_HANDLE keyHandle;
        ValidateStatus(L"ERR: The function BCryptGenerateSymmetricKey has failed.", BCryptGenerateSymmetricKey(encAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
        DWORD cbCipherText = 0;
        ValidateStatus(L"ERR: The function BCryptEncrypt (determine size) has failed.", BCryptEncrypt(
            keyHandle,
            fileContent.data(),
            static_cast<ULONG>(fileContent.size()),
            NULL,
            iv.data(),
            static_cast<ULONG>(iv.size()),
            NULL,
            0,
            &cbCipherText,
            BCRYPT_BLOCK_PADDING
        ));
        std::vector<BYTE> cipherText(cbCipherText);
        ValidateStatus(L"ERR: The function BCryptEncrypt has failed.", BCryptEncrypt(
            keyHandle,
            fileContent.data(),
            static_cast<ULONG>(fileContent.size()),
            NULL,
            iv.data(),
            static_cast<ULONG>(iv.size()),
            cipherText.data(),
            cbCipherText,
            &cbCipherText,
            BCRYPT_BLOCK_PADDING
        ));
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(encAlgHandle, 0);
        std::vector<BYTE> encryptedContent;
        encryptedContent.insert(encryptedContent.end(), originalIV.begin(), originalIV.end());
        encryptedContent.insert(encryptedContent.end(), cipherText.begin(), cipherText.end());
        std::wstring outputFileName = std::wstring(file) + L".locked";
        WriteFileContent(encryptedContent, outputFileName.c_str());
        std::wcout << L"MSG: The file has been locked successfully." << std::endl;
    }

    void UnlockFile() {
        AnnounceOperation(L"Unlocking the file.");
        std::vector<BYTE> encryptedContent = ReadFileContent();
        if (encryptedContent.size() < 16) {
            throw std::runtime_error("ERR: The file format is invalid.");
        }
        std::vector<BYTE> iv(encryptedContent.begin(), encryptedContent.begin() + 16);
        std::wcout << L"MSG: The initialization vector (IV) is:" << std::endl;
        DisplayHex(iv.data(), iv.size());
        std::vector<BYTE> cipherText(encryptedContent.begin() + 16, encryptedContent.end());
        std::vector<BYTE> key = CreateKey();
        BCRYPT_ALG_HANDLE decAlgHandle;
        ValidateStatus(L"ERR: The function BCryptOpenAlgorithmProvider has failed.", BCryptOpenAlgorithmProvider(&decAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
        ValidateStatus(L"ERR: The function BCryptSetProperty has failed.", BCryptSetProperty(decAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
        BCRYPT_KEY_HANDLE keyHandle;
        ValidateStatus(L"ERR: The function BCryptGenerateSymmetricKey has failed.", BCryptGenerateSymmetricKey(decAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
        std::vector<BYTE> decryptedText(cipherText.size());
        DWORD cbData = 0;
        NTSTATUS status = BCryptDecrypt(
            keyHandle,
            cipherText.data(),
            static_cast<ULONG>(cipherText.size()),
            NULL,
            iv.data(),
            static_cast<ULONG>(iv.size()),
            decryptedText.data(),
            static_cast<ULONG>(decryptedText.size()),
            &cbData,
            BCRYPT_BLOCK_PADDING
        );
        if (MSAES256FE_SUCCESS(status)) {
            BCryptDestroyKey(keyHandle);
            BCryptCloseAlgorithmProvider(decAlgHandle, 0);
            decryptedText.resize(cbData);
            std::wstring outputFileName = std::wstring(file) + L".unlocked";
            WriteFileContent(decryptedText, outputFileName.c_str());
            std::wcout << L"MSG: The file has been unlocked successfully." << std::endl;
            return;
        }
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(decAlgHandle, 0);
        ShowError(L"ERR: The function BCryptDecrypt has failed.", status);
        throw std::runtime_error("ERR: Unlocking the file has failed.");
    }
};

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc != 4) {
            std::wcerr << L"ERR: Usage: " << argv[0] << L" <filename> <password> <lock/unlock>" << std::endl;
            return 1;
        }
        MSAES256_FileEncryption MSAES256_FileEncryption(argv[1], argv[2], argv[3]);
        MSAES256_FileEncryption.Execute();
    }
    catch (const std::exception& ex) {
        std::cerr << "ERR: An error occurred: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
#endif // MSAES256FE_SECURE_H
