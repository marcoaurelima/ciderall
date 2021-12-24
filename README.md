# ciderall

Este Programa mostra algumas informações da rede de forma decimal e binária.<br>
Através do endereço IP + CIDR, ele apresenta a máscara de sub-rede, endereço de broadcast, o range de host dessa rede, máximo de sub-redes e máximo de endereços IP.

Exemplo:

$ ./ciderall 192.168.0.1/18

  input: [192.168.0.1/18]

 add.IP: [   192  .   168  .   0    .   1    ]<br>
         [11000000.10101000.00000000.00000001]<br>

 s.mask: [   255  .   255  .   192  .   0    ]<br>
         [11111111.11111111.11000000.00000000]<br>

  range: [network]       [broadcast]  
         [192.168.0.0]   [192.168.63.255] <br>
        N[11000000.10101000.00000000.00000000] <br>
        B[11000000.10101000.00111111.11111111]<br>

 max.subnets: [16384]    max.address:[16382]
