# CS165 HW1 
## Ashly Hernandez, SID: 862018436
 The code is able to transfer data from the client to the server. I was able to create the 20 packets 
and send them through the CRC32 function. All of the data is set before it is to be encrypted.
The program crashes when trying to pass into the RC4_set_key algorithm. There is a segmentation fault. 

## Next steps
Next i would pass the encrypted data along with the IV to carls-wep. From there i would intercept every other packet and change the destination address and send that to the AP. From there i would decrypt and output the header info and message. 
