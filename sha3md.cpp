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

//------ GLOBAL CONSTANTS & VARIABLES ------

static const char *kSummary = "Usage: sha3md [OPTIONS]... file...\n\
Print digest of files using SHA3/SHAKE algorithm.\n\
    file...         Files to digest (default is stdin)\n\
[OPTIONS]\n\
    --help          Display this summary\n\
    -[hash_type]    Algorithm type: SHA3-224, SHA3-256, SHA3-384, SHA3-512,\n\
                                    SHAKE128, SHAKE256\n\
    -len digestlen  FOR SHAKE ONLY: length of the digest (in bits!)\n\
    -out outfile    Output to filename rather than stdout\n\
    -sep character  Byte separator character in output string\n\
    -u              UPPERCASE mode for output string\n\
\n\
Examples:\n\
    sha3md -SHA3-256 -sep ':' file1.bin some_app.exe another_file.txt\n\
    sha3md -SHAKE128 -len 213 -out list_of_hashes.txt 'I wanna hashing.pdf'\n\
";

enum ErrCode: int {
    kError = -2, kBadParam = -1, kOk = 0,
    kHelp = 0x01, kLen = 0x02, kOut = 0x04, kSep = 0x08, kUpper = 0x10
};

static std::map<int, std::string> kParams = {
    {kHelp, "--help"},
    {224, "-SHA3-224"}, {256, "-SHA3-256"}, {384, "-SHA3-384"},
    {512, "-SHA3-512"}, {129, "SHAKE128"}, {257, "SHAKE256"},
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
inline void hash_setup(chash::SHA3Param &param, const int digest_size)
{
    param.cap = digest_size * 2;
    if ((127 == digest_size) or (257 == digest_size)) {
        param.d_size = digest_size - 1;
        param.dom = chash::kDomSHAKE;
    }
    else {
        param.d_size = digest_size;
        param.dom = chash::kDomSHA3;
    }
} // end hash_setup()


int check_param(const char* arg);
int update_hash_from_stream(std::istream &is,  chash::SHA3_IUF &hash);


//====== MAIN ======
int main(int argc, char *argv[])
{
    chash::SHA3Param hash_param;

    if (1 == argc) {        // only one argument: print summary and exit (Ok)
        return (print_summary(kHelp));
    }
    else if (2 == argc){    // either '--help' or default setup (only SHA/SHAKE)
        int res = check_param(argv[1]);
        if(kHelp == res)
            return (print_summary(kOk));
        else if((128 == res) or (256 == res) or (384 == res) or (512 == res) or
                (129 == res) or (257 == res)) {
            hash_setup(hash_param, res);
        }
    }

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
int check_param(const char* arg)     // check for single parameter
{
    int state = kBadParam;
    for(const auto & param : kParams) {
        if(std::strcmp(param.second.c_str(), arg))
            return (param.first);
    }
    return(state);
} // end check_flag()

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
