#include <iostream>
#include <vector>
#include <bitset>
#include <cmath>

#define CLR_RED "\x1b[0;31m"
#define CLR_GRE "\x1b[0;32m"
#define CLR_YLW "\x1b[0;33m"
#define CLR_BLU "\x1b[0;34m"
#define CLR_PUR "\x1b[0;35m"
#define CLR_CYA "\x1b[0;36m"
#define CLR_WHT "\x1b[0;37m"

#define CLR_RED_B "\x1b[1;31m"
#define CLR_GRE_B "\x1b[1;32m"
#define CLR_YLW_B "\x1b[1;33m"
#define CLR_BLU_B "\x1b[1;34m"
#define CLR_PUR_B "\x1b[1;35m"
#define CLR_CYA_B "\x1b[1;36m"
#define CLR_WHT_B "\x1b[1;37m"

const int SIZE_ADD_IP = 32;

using namespace std;
using IPdec_t = vector<int>;
using IPbin_t = vector<string>;

using MASKdec_t = IPdec_t;
using MASKbin_t = IPbin_t;


int binTodec(const string& bin)
{
    int dec = 0;

    for(unsigned i=bin.size();i>0;--i)
    {
        if(bin[i-1] == '0'){ continue; }
        dec += pow(2, bin.size()-i);
    }
    return dec;
}


IPdec_t getIp_dec(const string& input)
{
    IPdec_t ipaddr_dec;

    string buff = "";
    for(auto& i : input)
    {
        if(i == '/')
        {
            ipaddr_dec.push_back(stoi(buff)); buff = "";
            break;
        } else
        if(i == '.')
        {
            ipaddr_dec.push_back(stoi(buff)); buff = "";
        }
        if(i != '.') { buff += i; }
    }

    return ipaddr_dec;
}

IPbin_t getIp_bin(const IPdec_t& ipaddr_dec)
{
    IPbin_t ipaddr_bin;

    for(auto& i : ipaddr_dec)
    {
        string buff = bitset<8>(i).to_string();
        ipaddr_bin.push_back(buff);
    }

    return ipaddr_bin;
}

int qtd_max_values_bits(const int qtd_bits)
{
    string bin{};

    for(int i=0;i<qtd_bits;i++)
    {
        bin += '1';
    }

    int dec = binTodec(bin);

    return (dec+1);

};

bool ip_is_valid(string ip_addr)
{
    auto ipaddr_dec = getIp_dec(ip_addr);

    for(auto& i : ipaddr_dec)
    {
        if(i<0 || i>255){ return false; };
    }

    auto pos = ip_addr.find('/');
    int cidr = stoi(ip_addr.substr(pos+1));

    if(cidr<0 || cidr>31){ return false; }

    return true;

}

int main(int argc, char** argv)
{

    cout << CLR_WHT_B << "\n\x1b[1;30;47m" << "  CIDERALL     <cidr analyzer>       M.Aurelio " << CLR_WHT << "\n\n";

    if(argc != 2 || !ip_is_valid(argv[1]) ){ cout << "[error] Please insert a valid IP Adress + cidr.\n\n"; exit(1); }



    string input(argv[1]);
    //string input = "111.110.110.221/18";

    auto pos = input.find('/');
    int cidr = stoi(input.substr(pos+1));


    cout << CLR_WHT "  input: " << CLR_WHT_B << "[" << input << "]" << endl<<endl;
    cout << CLR_WHT;

    /* Endereço IP */
    cout << CLR_WHT << " add.IP: ";
    IPdec_t ipaddr_dec = getIp_dec(input);
    IPbin_t ipaddr_bin = getIp_bin(ipaddr_dec);

    cout << CLR_WHT_B << "[";
    for(unsigned i=0; i<ipaddr_dec.size();i++)
    {
        if(to_string(ipaddr_dec[i]).size()==3){ cout << "   " << ipaddr_dec[i] << "  "; } else
        if(to_string(ipaddr_dec[i]).size()==2){ cout << "   " << ipaddr_dec[i] << "   "; } else
        if(to_string(ipaddr_dec[i]).size()==1){ cout << "   " << ipaddr_dec[i] << "    "; }

        if(i!=ipaddr_dec.size()-1){ cout << ".";}
    }
    cout << "]" << CLR_WHT << "\n         [";
    int cont = 0;
    for(unsigned i=0; i<ipaddr_bin.size();i++)
    {
        cout << ipaddr_bin[i];
        if(i!=ipaddr_dec.size()-1){ cout << ".";}
    }
    cout << "]";
    cout << endl << endl;


    /* Mascara de Sub-rede */
    cout << CLR_WHT << " s.mask: ";

    MASKbin_t maskbin;

    string buff = "";
    for(int i=0;i<SIZE_ADD_IP;i++)
    {
        if(i%8==0 && i!=0){ maskbin.push_back(buff); buff = "";}
        buff += (i < cidr)? "1" : "0";
        if(i==SIZE_ADD_IP-1){ maskbin.push_back(buff);}
    }

    cout << CLR_WHT_B << "[";
    for(unsigned i=0; i<maskbin.size();i++)
    {
        if(to_string(binTodec(maskbin[i])).size()==3){ cout << "   " << binTodec(maskbin[i]) << "  "; } else
        if(to_string(binTodec(maskbin[i])).size()==2){ cout << "   " << binTodec(maskbin[i]) << "   "; } else
        if(to_string(binTodec(maskbin[i])).size()==1){ cout << "   " << binTodec(maskbin[i]) << "    "; }

        if(i!=maskbin.size()-1){ cout << ".";}
    }
    cout << "]\n" << CLR_WHT << "         [";
    for(unsigned i=0; i<maskbin.size();i++)
    {
        cout << maskbin[i];
        if(i!=maskbin.size()-1){ cout << ".";}
    }
    cout << "]" << endl << endl;

    /* Range máximo de endereços IP */
    auto add_network   = ipaddr_bin;
    auto add_broadcast = ipaddr_bin;

    for(unsigned i=0;i<add_network.size();i++)
    {
        for(unsigned j=0;j<add_network[i].size();j++)
        {
            if(cont >= cidr){
                add_network[i][j] = '0';
                add_broadcast[i][j] = '1';
            }
            ++cont;
        }
    }


    cout << CLR_WHT << "  range:" << CLR_WHT << " [network]";
    int cont_spces = 0;
    for(unsigned i=0; i<add_network.size();i++)
    {
        cont_spces += to_string(binTodec(add_network[i])).size();
    }
    for(int i=0; i<((cont_spces+5)-9)+3;i++)
    {
        cout << " ";
    }

    cout << "[broadcast]  \n";
    cout << CLR_WHT << "         " << CLR_WHT_B << "[";
    for(unsigned i=0; i<add_network.size();i++)
    {
        cout << binTodec(add_network[i]);
        if(i!=add_network.size()-1){ cout << ".";}
    }
    cout << "]   ["  << CLR_WHT_B;
    for(unsigned i=0; i<add_broadcast.size();i++)
    {
        cout << binTodec(add_broadcast[i]);
        if(i!=add_broadcast.size()-1){ cout << ".";}
    }
    cout << "]\n";

    cout << CLR_WHT << "        N[";
    for(unsigned i=0; i<add_network.size();i++)
    {
        cout << add_network[i];
        if(i!=add_network.size()-1){ cout << ".";}
    }
    cout << "]\n";

    cout << "        B[";
    for(unsigned i=0; i<add_broadcast.size();i++)
    {
        cout << add_broadcast[i];
        if(i!=add_broadcast.size()-1){ cout << ".";}
    }
    cout << "]\n\n";

    cout << " max.subnets: [" << CLR_WHT_B << qtd_max_values_bits(SIZE_ADD_IP-cidr) << CLR_WHT << "]    max.address:[" << CLR_WHT_B  << qtd_max_values_bits(SIZE_ADD_IP-cidr) -2 << "]" << endl<<endl;


    return 0;
}
