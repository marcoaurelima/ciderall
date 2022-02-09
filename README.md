# ciderall

This software shows some informations about a network, in decimal and binary form.
Throught of IP Address + CIDR, it show the subnet mask, broadcast address, range, max sub-net and max IP Address. 

Example:

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
