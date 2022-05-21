/* 
 * sha3.cpp
 * 2022 Copyright © by Elijah Coleman
 */

//-----------------------------------------------------------------------------

#include "sha3_ec.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <map>
#include <memory>

//------ GLOBAL CONSTANTS & VARIABLES ------

static const char *kSummary = "Usage: sha3md [OPTIONS]... file...\n\
Print digest of files using SHA3/SHAKE algorithm.\n\
    file...         Files to digest (default is stdin)\n\
[OPTIONS]\n\
    --help          Display this summary\n\
    -[hash_type]    SHA3 type:  SHA3-224, SHA3-256, SHA3-384, SHA3-512,\n\
                                SHAKE128, SHAKE256\n\
    -len digestlen  FOR SHAKE ONLY: length of the digest (in bits!)\n\
    -out outfile    Output to filename rather than stdout\n\
    -sep 'sep'      Byte separator character in output string\n\
    -u              UPPERCASE mode for output string\n\
\n\
Examples:\n\
    sha3md -SHA3-256 -sep ':' file1.bin some_app.exe another_file.txt\n\
    sha3md -SHAKE128 -len 213 -out list_of_hashes.txt 'I wanna hashing.pdf'\n\
";

enum ErrCode: int {
    kBadParam  = -2, kError = -1, kOk = 0,
    kHelp = 0x01, kLen = 0x02, kOut = 0x04, kSep = 0x08, kUpper = 0x10
};

static const std::map<int, std::string> kParams = { // Reference parameters
    {kHelp, "--help"},
    {224, "-SHA3-224"}, {256, "-SHA3-256"},
    {384, "-SHA3-384"}, {512, "-SHA3-512"},
    {128 + 1, "SHAKE128"}, {256 + 1, "SHAKE256"},
    {kLen, "-len"}, {kOut, "-out"}, {kSep, "-sep"}, {kUpper, "-u"}
};

static const chash::size_t kBlockSize = 1024 * 1024; // Read block size (1MB)

//------ ADDITIONAL FUNCTIONS DECLARATION ------
inline int print_summary(ErrCode error_code)
{
    std::cout << kSummary;
    return (error_code);
} // end print_summary()

//------ Setup hash algorithm parameters ------
int check_param(const char* str);
chash::SHA3Param hash_setup(const chash::size_t hash_size);
int set_digest_length(const char* str);
int update_hash_from_stream(std::istream &is,  chash::SHA3_IUF &hash);


//====== MAIN ======
int main(int argc, char *argv[])
{
    if (1 == argc) {    // only one argument: just print summary and exit
        return (print_summary(kHelp));
    }

    chash::SHA3Param hash_param;    // default params == SHA3_256
    int hash_length = 0;
    std::unique_ptr<std::ostream, void (*)(std::ostream*)> os{ &std::cout, 
                                                               [](auto) {} };
    char sep = 0;
    bool uppercase = false;

    int arg = 1;
    while(arg < argc) {
        int res = check_param(argv[arg]);
        switch (res)  {
        case kHelp :                      // '--help'
            return (print_summary(kOk));
        case 129 :                        // [hash_type]
        case 224 :
        case 256 :
        case 257 :
        case 384 :
        case 512 :
            hash_param = hash_setup(static_cast<chash::size_t>(res));
            break;
        case kLen :                       // '-len digestlen'
            if ((arg + 1) != argc) {
                hash_length = set_digest_length(argv[arg + 1]);
                if (hash_length < 0)
                    return(kError);
                arg++;
            } else {
                std::cerr << "Digest length not specified!\n";
                return (kError);
            }
            break;
        case kOut :                         // '-out outfile'
            if ((arg + 1) != argc) {
                os = {  new std::ofstream(argv[arg + 1]), 
                        [](std::ostream* p) {delete p;}  };
                if (!os) {
                    std::cerr << "Error opening output file '"
                              << argv[arg + 1] << "'!\n";
                    return (kError);
                }
                arg++;
            } else {
                std::cerr << "Outfile is not specified!\n";
                return (kError);
            }
            break;                          
        case kSep :                         // '-sep character'
            if ((arg + 1) != argc) {
                sep = (std::strlen(argv[arg + 1]) == 1) ? argv[arg + 1][0] : 0;
                if (0 == sep) {
                    std::cerr << "Symbol-separator specified incorrect!\n";
                    return (kError);
                }
                //std::cout << "Separator '" << sep << "'\n";
                arg++;
            } else
                std::cerr << "Option '-sep' was declared, but no symbol was specified!\n";
            break;
        case kUpper :
            uppercase = true;
            break;
        case kBadParam :
            std::cerr << "Incorrect parameters. Use 'sha3sum --help' for more information.\n";
            return (kError);
        default:        // in this case: all next parameters specify filenames
            while (arg < argc) {
                std::cout << argv[arg];
                arg++;
            }
            break;
        } // end swithc(check_param)

        arg++;
    }  // end while(i)

    /*
        chash::SHA3Param param = chash::kSHA3_384;
        chash::SHA3_IUF hash(param);

        std::cout << "\n" << hash.get_hash_type() << "\n\n";

        hash.init();
        update_hash_from_stream(std::cin, hash);

        std::cout << "\n(stdin):";
        //hash.set_separator(' ');
        std::cout // << std::uppercase
                  << hash << std::nouppercase << std::endl;


        std::ifstream input_file (".testdata.bin", std::ios::in);

        if(input_file) {
            hash.init();
            update_hash_from_stream(input_file, hash);

            std::cout << "\n(.testdata.bin):";
            //hash.set_separator(' ');
            std::cout //<< std::uppercase
                      << hash << std::nouppercase << std::endl;

            input_file.close();
        }
    */



    return (kOk);
} // end main(...)

//------ DEFINITION FOR ADDITIONAL FUNCTIONS ------

//------ Check for single parameter ------
int check_param(const char* arg)
{
    int res = kBadParam;
    for (const auto& param : kParams) {
        if (std::strcmp(param.second.c_str(), arg) == 0)
            return (param.first);
    }
    return(res);
} // end check_param()

//------ Setup hast algorithm parameters ------
chash::SHA3Param hash_setup(const chash::size_t hash_size)
{
    switch (hash_size) {
    case 129 :
        return (chash::kSHAKE128);
    case 224 :
        return (chash::kSHA3_224);
    case 257 :
        return (chash::kSHAKE256);
    case 384 :
        return (chash::kSHA3_384);
    case 512 :
        return (chash::kSHA3_512);
    case 256:
    default :
        return (chash::kSHA3_256);
    }
} // end hash_setup()

//----------------------------------------
int set_digest_length(const char* str)
{
    int len = 0;
    try {
        len = std::stoi(str);
    }
    catch (std::invalid_argument const& ex) {
        std::cerr << "Invalid digest length: " << ex.what() << '\n';
        return (kError);
    }
    catch (std::out_of_range const& ex) {
        std::cerr << "Digest length is out of range: " << ex.what() << '\n';
        return (kError);
    }
    return (len);
} // end set_digest_length()

//------ Read from input stream ------
int update_hash_from_stream(std::istream &is,  chash::SHA3_IUF &hash)
{
    if (is) {
        std::string buf(kBlockSize, 0); // string size 1MB, each char = 0
        while(is.good()) {
            is.read(&buf.front(), kBlockSize);
            if((is.fail() and !is.eof()) or is.bad()) {
                std::cerr << "Error reading from file!\n";
                return (kError);
            }
            hash.update(buf.begin(), buf.begin() + is.gcount());
        }
    }
    else {
        std::cerr << "Error reading from file!\n";
        return (kError);
    }
    return (kOk);
} // end update_hash_from_stream()

//-----------------------------------------------------------------------------
