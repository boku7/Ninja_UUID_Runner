# ModStomp_UUID2Shellcode_Dropper
 Dropper that loads DLL into memory, changes DLL .TEXT section to RW, decodes shellcode from UUID &amp; writes to DLL .TEXT section, changes DLL .TEXT section back to RX, and uses EnumSystemLocalesA() to jump to shellcode &amp; execute!
