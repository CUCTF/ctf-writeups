# PowerAnalysis: Part 1

This embedded system allows you to measure the power consumption of the CPU while it is running an AES encryption algorithm. Use this information to leak the key via dynamic power analysis.

Access the running server with `nc saturn.picoctf.net port`. It will encrypt any buffer you provide it, and output a trace of the CPU's power consumption during the operation. The flag will be of the format picoCTF{\<encryption key\>} where \<encryption key\> is 32 lowercase hex characters comprising the 16-byte encryption key being used by the program.
