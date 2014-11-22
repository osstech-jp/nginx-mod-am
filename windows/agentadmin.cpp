#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <wincrypt.h>

#include <iostream>
#include <string>
#include <fstream>
using namespace std;

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")

string generateKey(){
    HCRYPTPROV hProv = 0;
    BYTE agentEncryptKey[24];
    char key[48];
    DWORD keyLen;
    if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)){
        perror("error at CryptAcquireContext()");
        exit(EXIT_FAILURE);
    }

    if(!CryptGenRandom(hProv, sizeof(agentEncryptKey), agentEncryptKey)){
        perror("error at CryptGenRandom()");
        exit(EXIT_FAILURE);
    }
    if(!CryptReleaseContext(hProv, 0)){
        perror("error at CryptReleaseContext()");
        exit(EXIT_FAILURE);
    }
    if(!CryptBinaryToString(agentEncryptKey, sizeof(agentEncryptKey),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                            key, &keyLen)){
        perror("error at CryptBinaryToString()");
        exit(EXIT_FAILURE);
    }
    return string(key, keyLen);
}

string cryptPassword(string cryptCmd, string password, string key){
    string cmd = "\"" + cryptCmd + "\" " + password + " " + key;
    //cout << "cmd: " << cmd << "\n";
    FILE *pipe = _popen(cmd.c_str(), "r");
    char buf[1024];
    if(!pipe){
        perror("error at popen()");
        exit(EXIT_FAILURE);
    }
    fgets(buf, sizeof(buf), pipe);
    return string(buf);
}

int main(int argc, char *argv[]){
    char path[_MAX_PATH];
    GetModuleFileName(NULL, path, sizeof(path));
    string modulePath = string(path);
    string baseDir = modulePath.substr(0, modulePath.find_last_of("\\/"));
    string logsDir = baseDir + "\\logs";
    string confDir = baseDir + "\\conf";
    string cryptCmd = baseDir + "\\bin\\cryptit.exe";
    string bootstrapFile = confDir + "\\OpenSSOAgentBootstrap.properties";
    string bootstrapTmpl = confDir + "\\OpenSSOAgentBootstrap.template";
    string openamUrl;
    string agentProfileName;
    string agentPassword;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);

    cout << "\
************************************************************************\n\
Welcome to the OpenSSO Policy Agent for NGINX\n\
************************************************************************\n\
";
    cout << "Enter the URL where the OpenAM server is running.\n";
    cout << "Please include the deployment URI also as shown below:\n";
    cout << "(http://openam.sample.com:58080/openam)\n";
    do{
        cout << "OpenAM server URL: ";
        getline(cin, openamUrl);
    }while(openamUrl.empty());

    cout << "Enter the Agent profile name\n";
    do{
        cout << "Agent Profile Name: ";
        getline(cin, agentProfileName);
    }while(agentProfileName.empty());

    cout << "Enter the password to be used for identifying the Agent.\n";
    cout << "*THIS IS NOT PASSWORD FILE*\n";
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    do{
        cout << "Agent Password: ";
        getline(cin, agentPassword);
        cout << "\n";
    }while(agentPassword.empty());
    SetConsoleMode(hStdin, mode);

    string agentEncryptKey = generateKey();
    string agentEncryptedPassword = cryptPassword(cryptCmd,
                                                  agentPassword,
                                                  agentEncryptKey);

    cout << "\
-----------------------------------------------\n\
SUMMARY OF YOUR RESPONSES\n\
-----------------------------------------------\n\
";
    cout << "OpenSSO server URL : " << openamUrl << endl;
    cout << "Agent Profile name : " << agentProfileName << endl;
    cout << endl;
    cout << "Continue with Installation?\n";
    string input;
    do{
        cout << "[y/N]: ";
        getline(cin, input);
        if(!input.compare("N") || !input.compare("n")){
            exit(EXIT_SUCCESS);
        }
        if(!input.compare("Y") || !input.compare("y")){
            break;
        }
    }while(1);


    ifstream ifs(bootstrapTmpl);
    if(!ifs){
        perror("Cannot open template file");
        exit(EXIT_FAILURE);
    }
    ofstream ofs(bootstrapFile);
    if(!ofs){
        perror("Cannot open output file");
        exit(EXIT_FAILURE);
    }
    string line;
    int index;
    while(getline(ifs, line)){
        index = line.find("@OPENAM_URL@");
        if(index > 0){
            line.replace(index, 12, openamUrl);
        }
        index = line.find("@AGENT_PROFILE_NAME@");
        if(index > 0){
            line.replace(index, 20, agentProfileName);
        }
        index = line.find("@AGENT_ENCRYPTED_PASSWORD@");
        if(index > 0){
            line.replace(index, 26, agentEncryptedPassword);
        }
        index = line.find("@AGENT_ENCRYPT_KEY@");
        if(index > 0){
            line.replace(index, 19, agentEncryptKey);
        }
        index = line.find("@AGENT_LOGS_DIR@");
        if(index > 0){
            line.replace(index, 16, logsDir);
        }
        ofs << line << endl;
    }
    ifs.close();
    ofs.close();
    cout << "Generated " << bootstrapFile << endl;
    cout << "Enter any key to exit." << endl;
    // pause
    getline(cin, input);
    return EXIT_SUCCESS;
}
