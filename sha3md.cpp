/* 
 * sha3.cpp
 * 2022 Copyright © by Elijah Coleman
 */

//=============================================================================

#include "sha3_ec.h"

#include <fstream>
#include <cstring>
#include <map>
#include <memory>

//=============================================================================
enum ErrCode { kOk = 0, kError};

static int print_summary(int exit_code)
{
    std::cout << "Usage: sha3md [OPTIONS]... file..."
        << "\nPrint digest of files using SHA3/SHAKE algorithm."
        << "\n  file...         Files to digest (default is stdin)"
        << "\n[OPTIONS]"
        << "\n  --help          Display this summary"
        << "\n  -[hash_type]    Hash type : SHA3-224, SHA3-256, SHA3-384"
        << "\n                              SHA3-512, SHAKE128, SHAKE256"
        << "\n  -len digestlen  FOR SHAKE ONLY : length of a digest(in bits!)"
        << "\n  -out outfile    Output to file rather than stdout"
        << "\n  -sep 'sep'      Byte separator character in output string"
        << "\n  -u              Output in UPPERCASE (default: lowercase)"
        << "\nEXIT STATUS :"
        << "\n  0               Successful completion"
        << "\n  1               An error occures"
        << "\nEXAMPLES:"
        << "\n  sha3md -SHA3-256 -sep ':' file1.bin some_app.exe"
        << "\n  sha3md -SHAKE128 -len 213 -out sha3.sum 'I wanna hashing.pdf'"
        << std::endl;
    return (exit_code);
} // end print_summary()

//=============================================================================

class SHA3Hash 
{
    using istream_ptr = std::unique_ptr<std::istream, void (*)(std::istream*)>;
    using ostream_ptr = std::unique_ptr<std::ostream, void (*)(std::ostream*)>;
    using buf_type = std::unique_ptr<char[], std::default_delete<char[]>>;
    enum ParamCode { len, out, sep, upper, sha3_224, sha3_256, sha3_384,
                     sha3_512, shake128, shake256, bad_param  };
public:
    SHA3Hash();
   
    int set_param(const int first, const char* params[]);
    int print_digest();
private:
    int check_param(const char* arg) const;
    chash::SHA3Param set_hash_type(int hash_type);
    chash::size_t set_length(const char* param);
    int set_input_files();
    int update_hash_from_stream(const istream_ptr& is, buf_type& buffer,
                                chash::SHA3_IUF& obj);
private:
    const int block_size_ = 1024 * 1024;  // reading block size (8MB)
    chash::SHA3Param sha3_param_;
    chash::size_t hash_length_;
    std::vector<std::string> input_from_;
    ostream_ptr output_to_;
    bool ready_;
    bool uppercase_;
    char separator_;
};  // end class SHA3Hash declaration

//=============================================================================
//************************* MAIN **********************************************
//=============================================================================
int main(int argc, const char* argv[])
{
    if (1 == argc or (2 == argc and (std::strcmp(argv[1], "--help") == 0))) {
        return (print_summary(kOk));
    }
    SHA3Hash hash;
    if(kError == hash.set_param(argc, argv))
        return (kError);
    return (hash.print_digest());
} // end main(...)

//=============================================================================
//------ Class SHA3Hash ------
SHA3Hash::SHA3Hash()
:   sha3_param_(chash::kSHA3_256),      // default - use SHA3-256
    hash_length_(0),
    output_to_({ &std::cout, [](auto) {} }),
    ready_(false),
    uppercase_(false),
    separator_(0)
{
    input_from_.push_back("stdin");
} // end SHA3Hash::SHA3Hash()

//---------------------------------------------------------
int SHA3Hash::set_param(const int argc, const char* argv[])
{
    int arg_num = 1;
    while (arg_num < argc) {
        int res = check_param(argv[arg_num]);
        switch (res) {  // SWITCH (RES)
        case sha3_224:                      // 'hash-type'
        case sha3_256:
        case sha3_384:
        case sha3_512:
        case shake128:
        case shake256:
            sha3_param_ = set_hash_type(res);
            ready_ = true;
            break;
        case len:                           // '-len digestlen'
            if ((arg_num + 1) != argc) {
                hash_length_ = set_length(argv[arg_num + 1]);
                if (!hash_length_)
                    return(kError);         // if 'digestlen' not specified
                arg_num++;
            } else {
                std::cerr << "Digest length not specified!\n";
                return (kError);
            }
            break;
        case out:                           // '-out outfile'
            if ((arg_num + 1) != argc) {
                output_to_ = { new std::ofstream(argv[arg_num + 1], std::ios::out),
                                        [](std::ostream* p) {delete p; } };
                if (!(*output_to_)) {
                    std::cerr << "Error opening file '"
                        << argv[arg_num + 1] << "' for output!\n";
                    return (kError);
                }
                arg_num++;
            } else {
                std::cerr << "Outfile is not specified!\n";
                return (kError);
            }
            break;
        case sep:                         // '-sep character'
            if ((arg_num + 1) != argc) {
                separator_ = argv[arg_num + 1][0];
                arg_num++;
            } else {
                std::cerr << "Option '-sep' was declared, but no symbol was specified!\n";
                return (kError);
            }
            break;
        case upper:
            uppercase_ = true;
            break;
        case bad_param:
            if (ready_) {       // all rest parameters are the filenames
                input_from_.pop_back();     // delete "stdint"
                while (arg_num < argc) {
                    input_from_.push_back(argv[arg_num]);
                    arg_num++;
                }
            } else {
                std::cerr << "Incorrect parameters!\n"
                          << "Use 'sha3sum --help' for help." << std::endl;
                return (kError);
            }
        default:
            static_assert(true, "Critical Error: unknown parameter!");
        } // end swithc(check_param)
        arg_num++;
    } // end while (arg_num)
    return (kOk);
} // end set_param()

//--------------------------
int SHA3Hash::print_digest()
{
    chash::SHA3_IUF sha3_obj(sha3_param_);
    if (separator_)
        sha3_obj.set_separator(separator_);
    if (hash_length_ != 0)
        sha3_obj.set_digest_size(hash_length_);
    buf_type buf = std::make_unique<char[]>(block_size_);
    for (const std::string &ifname : input_from_) { // Input files processing
        istream_ptr in_stream{ nullptr, [](auto) {} };
        if ("stdin" == ifname)           // If the input file is not specified
            in_stream = { &std::cin, [](auto) {} };    // use standard input
        else
            in_stream = { new std::ifstream(ifname, (std::ios_base::in | std::ios_base::binary)), 
                                            [](std::istream* p) {delete p; } };
        if (*in_stream) {
            sha3_obj.init();                // init hash object
            int res = update_hash_from_stream(in_stream, buf, sha3_obj);
            if(res)                 // an error occurred when reading from file
                break;          
            // print result
            *output_to_ << sha3_obj.get_hash_type() << "(" << ifname << ")= ";
            if (uppercase_)
                *output_to_ << std::uppercase;
            *output_to_ << sha3_obj << std::endl;
        }
        else {
            std::cerr << "(" << ifname << ") - Error opening file!\n";
        }
    } // end for(ifname...)
    return (kOk);
} // end print_digest()

//----------------------------------------------
int SHA3Hash::check_param(const char* arg) const
{
    // Reference parameters
    static const std::map<int, std::string> ref_params = {
        {sha3_224, "-SHA3-224"}, {sha3_256, "-SHA3-256"}, 
        {sha3_384, "-SHA3-384"}, {sha3_512, "-SHA3-512"}, 
        {shake128, "SHAKE128"}, {shake256, "SHAKE256"},
        {len, "-len"}, {out, "-out"}, {sep, "-sep"}, {upper, "-u"}
    };
    int res = bad_param;
    for (const auto& param : ref_params) {
        if (std::strcmp(param.second.c_str(), arg) == 0)
            return (param.first);
    }
    return(res);
} // end SHA3Hash::check_param(...)

//-----------------------------------------------------
chash::SHA3Param SHA3Hash::set_hash_type(int hash_type)
{
    switch (hash_type) {
    case sha3_224:
        return (chash::kSHA3_224);
    case sha3_256:
        return (chash::kSHA3_256);
    case sha3_384:
        return (chash::kSHA3_384);
    case sha3_512:
        return (chash::kSHA3_512);
    case shake128:
        return (chash::kSHAKE128);
    case shake256:
        return (chash::kSHAKE256);
    default:
        return (chash::kSHA3_256);      // by default SHA3-256
    }
} // end SHA3Hash::set_hash_type(...)

//---------------------------------------------------
chash::size_t SHA3Hash::set_length(const char* param)
{
    chash::size_t len = 0;
    try {
        len = std::stoll(param);
    }
    catch (std::exception const& ex) {
        std::cerr << "Invalid parameter (digest length)!\n"
            << "Use 'sha3md --help' for help." << std::endl;
        return (0);
    }
    return (len);
} // end SHA3Hash::set_length(...)

//---------------------------------------------------------------------------
int SHA3Hash::update_hash_from_stream(const istream_ptr& is, buf_type &buffer,
                                      chash::SHA3_IUF& obj)
{
    while (is->good()) {
        is->read(buffer.get(), block_size_);
        if ((is->fail() and !is->eof()) or is->bad()) {
            std::cerr << "Error reading from file!\n";
            return (kError);
        }
        obj.update(buffer.get(), is->gcount()); // update hash
    }
    return (kOk);
} // end SHA3Hash::update_hash_from_stream()

//=============================================================================
