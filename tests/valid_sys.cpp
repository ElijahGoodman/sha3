/******************************************************************************
 * Cryptographic Algorithm Validation Program (CAVP),
 * based on
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 *
 * 2022 Copyright © by Elijah Coleman
 *
 *****************************************************************************/

#include "sha3_ec.h"

#include <filesystem>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <regex>

//-----------------------------------------------------------------------------
using dgst_vec = const std::vector<chash::byte>;

void sha3_test(const std::string &dir);

//=============================================================================
int main(int argc, char** argv)
{
    std::cout << "Check connection...OK\n";
    
    std::string dirs[] = {
        "sha3_bit_test_vectors/", "sha3_byte_test_vectors/",
        "shake_bit_test_vectors/", "shake_byte_test_vectors/"
    };
    
    for (const auto& dir : dirs) {
        if (std::filesystem::exists(dir)) {
            std::cout << "Checking " << dir << std::endl;
            sha3_test(dir);
        }
        else
            std::cerr << "Directory " << dir << "not found." << std::endl;
    }
 
    std::cout << "The end.\n";
    return (0);
} // end main()
//=============================================================================

//-----------------------------------------------------------
std::ostream& operator<<(std::ostream& os,
                         const std::vector<chash::byte> &vec)
{
    os << std::hex << std::setfill('0');
    for(const auto elem : vec)
        os << std::setw(2) << int(elem);
    return (os);
} // end operator<<(...const vector<byte>)

//-------------------------------------------------
std::string convert_raw_str(const std::string& str)
{
    if (str.empty())
        return ("");
    std::string res(str.length()/2, 0);
    for(unsigned i = 0; i < str.size()-1; i += 2) {
        res[i/2] = static_cast<char>(std::stoi(str.substr(i, 2), nullptr, 16));
    }
    return (res);
} // end convert_raw_str(...)

//---------------------------------------------------------------
bool cmp_dgst(const dgst_vec &&dgst, const std::string &ref_dgst)
{
    if(dgst.size() != (ref_dgst.size()/2))
        return (false);
    std::stringstream sstr;
    sstr << dgst;
    return (sstr.str() == ref_dgst);
} // end cmp_dgst(...)

//----------------------------------------------------------------------
inline int check_hash(chash::SHA3_IUF *hash_obj, const std::string& msg, 
               chash::size_t msg_len, const std::string &msg_hash, 
               unsigned line_num, bool byte_oriented)
{
    if (byte_oriented) {
        hash_obj->init();
        hash_obj->update(msg.c_str(), msg_len / chash::k8Bits);
        if (!cmp_dgst(hash_obj->finalize(), msg_hash)) {
            std::cout << "\n    Hash does not match: line " << line_num;
            return (1);
        }
    }
    else {
        if (!cmp_dgst(hash_obj->get_digest(msg, msg_len), msg_hash)) {
            std::cout << "\n    Hash does not match: line " << line_num;
            return(1);
        }
    }
    return (0);
} // end check_hash(...)

//-------------------------------------------
inline void print_checking_result(int failed)
{
    std::cout << (0 == failed ? "    SUCCESS."
            : "\n    FAIL (" + std::to_string(failed) + " mismatches found).")
              << std::endl;
} // end print_checking_result(...)

//---------------------------------------------------------
void long_short_msg(std::ifstream &ifs, bool byte_oriented)
{
    int failed = 0;
    chash::SHA3Param param;
    chash::SHA3_IUF hash_obj;
    std::regex len_patt(R"(\[?(L|Len|Outputlen) = (\d+)\]?)");
    std::regex msg_patt(R"((Msg) = *)");
    std::regex hash_patt(R"((MD|Output) = ([A-Fa-f0-9]+))");
    std::string msg;
    std::string msg_hash;
    chash::size_t msg_len(0);
    unsigned line_num = 0;
    for(std::string line; std::getline(ifs, line); line_num += 1) {
        if ('#' == line[0] or line.empty())   // skip comments and empty string
            continue;
        std::smatch matches;
        // for "[L = ...]", "[Ouputlen = 256]" and "Len = ..."
        if (std::regex_match(line, matches, len_patt)) {
            chash::size_t len = std::stoll(matches[2].str());
            if ("L" == matches[1].str()) {
                param.hash_size = static_cast<chash::HashSize>(len);
                hash_obj.setup(param);
            }
            else if ("Outputlen" == matches[1].str()) {
                param.dom = chash::Domain::kDomSHAKE;
                param.hash_size = static_cast<chash::HashSize>(len);
                hash_obj.setup(param);
            }
            else if ("Len" == matches[1].str())
                msg_len = len;
            continue;
        }
        // for "Msg = ..."
        else if (std::regex_search(line.begin(), line.end(), msg_patt)) {
            auto pos = line.find('=') + 2;
            msg = convert_raw_str(line.substr(pos, line.length() - pos));
            continue;
        }
        // for "MD = ..." and "Output = ..."
        else if (std::regex_match(line, matches, hash_patt)) {
            // calculate the hash and compare it with the sample
            msg_hash = matches[2].str();
            failed += check_hash(&hash_obj, msg, msg_len, msg_hash, line_num, byte_oriented);
        } // end for block if(regex_match()....)
    } // end for(line...)
    print_checking_result(failed);
} // end long_short_msh(...)

//----------------------------------
void monte_carlo(std::ifstream& ifs)
{
    chash::SHA3Param param;
    chash::SHA3_IUF hash_obj;
    std::regex len_patt(R"(\[L = (\d+)\])");
    std::regex seed_patt(R"(Seed = ([A-Fa-f0-9]+))");
    std::regex hash_patt(R"(MD = ([A-Fa-f0-9]+))");
    std::string seed;
    std::string md;
    unsigned line_num = 0;
    for (std::string line; std::getline(ifs, line); line_num += 1) {
        if ('#' == line[0] or line.empty())   // skip comments and empty string
            continue;
        std::smatch matches;
        if (std::regex_match(line, matches, len_patt)) {    // for "[L = ...]"
            chash::size_t len = std::stoll(matches[1].str());
                param.hash_size = static_cast<chash::HashSize>(len);
                hash_obj.setup(param);
            continue;
        }
        else if (std::regex_match(line, matches, seed_patt)) {  // for "Seed = ..."
            seed = convert_raw_str(matches[1]);
            continue;
        }
        else if (std::regex_match(line, matches, hash_patt)) { // for "MD = ..."
            // Start generation. 
            md = matches[1].str();
            for (int i = 0; i < 1000; i++)
                hash_obj.get_digest(seed, seed);
            // Checkpoint
            if (seed != convert_raw_str(md)) {
                std::cout << "\n    Hash does not match: line " << line_num;
                std::cout << "\n    FAIL." << std::endl;
                return;
            }
        } // end for block if(regex_match()....)
    } // end for(line...)
    std::cout << "    SUCCESS." << std::endl;
} // end monte_carlo(...)

//-------------------------------------------------------
void monte_carlo_shake(std::ifstream& ifs, bool shake256)
{
    chash::SHA3_IUF hash_obj;
    if (shake256)
        hash_obj.setup(chash::kSHAKE256);
    else
        hash_obj.setup(chash::kSHAKE128);

    unsigned line_num(0);
    std::string msg;
    chash::size_t min_out_len(0), max_out_len(0), 
                  out_len(0), ref_out_len(0), range(0);
    std::string output;
    std::regex len_patt(R"(Outputlen = (\d+))");
    std::regex msg_patt(R"(Msg = ([A-Fa-f0-9]+))");
    std::regex out_patt(R"(Output = ([A-Fa-f0-9]+))");
    std::regex min_patt(R"(\[Minimum Output Length \(bits\) = (\d+)\])");
    std::regex max_patt(R"(\[Maximum Output Length \(bits\) = (\d+)\])");
    for (std::string line; std::getline(ifs, line); line_num += 1) {
        if ('#' == line[0] or line.empty())   // skip comments and empty string
            continue;
        std::smatch matches;
        if (std::regex_match(line, matches, msg_patt)) {  // for "Msg = ..."
            msg = convert_raw_str(matches[1]);
            continue;
        }
        else if (std::regex_match(line, matches, min_patt)) { // for "Min output len..."
            min_out_len = std::stoll(matches[1].str()) / 8;     // in bytes
            continue;
        }
        else if (std::regex_match(line, matches, max_patt)) { // for "Max output len..."
            max_out_len = std::stoll(matches[1].str()) / 8;     // in bytes
            out_len = max_out_len;                              // in bytes
            range = max_out_len - min_out_len + 1;              // in bytes
            continue;
        }
        else if (std::regex_match(line, matches, len_patt)) { // for "Outputlen = ..."
            ref_out_len = std::stoll(matches[1].str());
            continue;
        }
        else if (std::regex_match(line, matches, out_patt)) { // for "Output = ..."
            output = matches[1].str();
            // Start generation. 
            for (int i = 0; i < 1000; i++) {
                msg.resize(16, 0);      // 128 leftmost bits of Output[i-1]
                hash_obj.set_digest_size(out_len * 8);
                hash_obj.get_digest(msg, msg);
                unsigned right_bits = 0xFFFF & unsigned(msg[msg.size() - 2]) << 8;
                right_bits |= chash::byte(msg[msg.size() - 1]);
                out_len = min_out_len + (right_bits % range);
            } // end for(i...)
            // Checkpoint
            if (msg != convert_raw_str(output)) {
                std::cout << "\n    Hash does not match: line " << line_num;
                std::cout << "\n    FAIL." << std::endl;
                return;
            }
        } // end for block if(regex_match()....)
    } // end for(line...)
    std::cout << "    SUCCESS." << std::endl;
} // end monte_carlo(...)

//----------------------------------------------------------
void variable_output(std::ifstream& ifs, bool byte_oriented)
{
    int failed = 0;
    chash::SHA3_IUF hash_obj(chash::kSHAKE128);
    std::regex len_patt(R"(\[?(Input Length|Outputlen) = (\d+)\]?)");
    std::regex msg_patt(R"((Msg) = *)");
    std::regex hash_patt(R"(Output = ([A-Fa-f0-9]+))");
    std::string msg;
    std::string msg_hash;
    unsigned line_num = 0;
    for (std::string line; std::getline(ifs, line); line_num += 1) {
        if ('#' == line[0] or line.empty())   // skip comments and empty string
            continue;
        std::smatch matches;
        // for "[Input Length = ...]" and "Ouputlen = ..."
        if (std::regex_match(line, matches, len_patt)) {
            chash::size_t len = std::stoll(matches[2].str());
            if ("Input Length" == matches[1].str() and len == 256) // for SHAKE256
                    hash_obj.setup(chash::kSHAKE256);
            else if ("Outputlen" == matches[1].str())
                hash_obj.set_digest_size(len);
            continue;
        }
        // for "Msg = ..."
        else if (std::regex_search(line.begin(), line.end(), msg_patt)) {
            auto pos = line.find('=') + 2;
            msg = convert_raw_str(line.substr(pos, line.length() - pos));
            continue;
        }
        // for "Output = ..."
        else if (std::regex_search(line.begin(), line.end(), hash_patt)) {
            // calculate the hash and compare it with the sample
            auto pos = line.find('=') + 2;
            msg_hash = line.substr(pos, line.length() - pos);
            failed += check_hash(&hash_obj, msg, msg.size()*8, msg_hash, line_num, byte_oriented);
        } // end for block if(regex_match()....)
    } // end for(line...)
    print_checking_result(failed);
}  // end variable_output(...)

//---------------------------------------
void sha3_test(const std::string &dir)
{
    bool byte_oriented = (dir.find("byte") != std::string::npos);
    bool shake_test = (dir.find("shake") != std::string::npos);
    // Iterate throw files of directory "path"
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        // trying opening file
        std::string fname = entry.path().string();
        std::ifstream ifs(fname);
        if (!ifs) {
            std::cerr << "  Error opening file " << fname << std::endl;
            continue;
        }
        std::cout << "  Processing " << fname;

        // Determine type of file
        bool short_msg = (fname.find("ShortMsg") != std::string::npos);
        bool long_msg = (fname.find("LongMsg") != std::string::npos);
        bool monte = (fname.find("Monte") != std::string::npos);
        bool var_out = (fname.find("VariableOut") != std::string::npos);

        // Determine SHA3/SHAKE parameters
        if (short_msg or long_msg)  // SHA3/SHAKE LongMsg / ShortMsg
            long_short_msg(ifs, byte_oriented);
        else if (monte) {           // Pseudorandomly generated message test
            if (shake_test)
                monte_carlo_shake(ifs, (fname.find("256") != std::string::npos));
            else
                monte_carlo(ifs);
        }
        else if (var_out)           // for XOFs (Variable Output Length)
            variable_output(ifs, byte_oriented);
        else
            std::cout << "    Unknown file type.\n";
        ifs.close();
    } // end for(entry...)

    return;
} // end sha3_bit_test(...)

//-----------------------------------------------------------------------------
