undefined8 main(void)

{
  char *pcVar1;
  basic_ostream *pbVar2;
  long in_FS_OFFSET;
  double dVar3;
  allocator local_156;
  allocator local_155;
  char local_154;
  char local_153;
  char local_152;
  char local_151;
  int local_150;
  undefined4 local_14c;
  basic_string local_148 [32];
  basic_string local_128 [32];
  basic_string local_108 [32];
  basic_string local_e8 [32];
  basic_string local_c8 [32];
  __cxx11 local_a8 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_88 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_68 [32];
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  long local_20;
 
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 3;
  local_44 = 7;
  local_40 = 1;
  local_3c = 9;
  local_38 = 4;
  local_34 = 6;
  local_30 = 2;
  local_2c = 8;
  local_28 = 5;
  local_14c = 9;
  processData(&local_48,9);
  local_150 = 3;
  local_154 = '\0';
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
  std::allocator<char>::allocator();
  pcVar1 = (char *)GetEncryptionKey2();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
  basic_string<std::allocator<char>>(local_68,pcVar1,&local_155);
  std::allocator<char>::allocator();
  pcVar1 = (char *)GetEncryptionKey();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
  basic_string<std::allocator<char>>(local_88,pcVar1,&local_156);
  std::operator+(local_e8,(basic_string *)local_88);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	(local_88);
  std::allocator<char>::~allocator((allocator<char> *)&local_156);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	(local_68);
  std::allocator<char>::~allocator((allocator<char> *)&local_155);
  objectparser(local_c8);
  do {
	pbVar2 = std::operator<<((basic_ostream *)std::cout,
                         	"\n____   _________   ____ ___.____  ___________\n\\   \\ /   /  _  \\  |	|   \\	| \\__	___/\n \\   Y   /  /_\\  \\|	|   /	|   | 	|   \n  \\ 	/	|	\\	|  /|	|___|	|   \n   \\___/\\_ ___|__  /______/ |_______ \\____|   \n            	\\/              	\\/    	\n    	"
                        	);
	std::operator<<(pbVar2,"\n\n");
	std::operator<<((basic_ostream *)std::cout,"Enter the vault key: ");
	std::operator>>((basic_istream *)std::cin,local_148);
	std::operator<<((basic_ostream *)std::cout,"Enter the vault password: ");
	std::operator>>((basic_istream *)std::cin,local_128);
	std::operator<<((basic_ostream *)std::cout,"Enter the number: ");
	std::operator>>((basic_istream *)std::cin,local_108);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
          	((basic_string *)local_68);
	dVar3 = (double)verifyingBypassKey(SUB81(local_68,0));
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_68);
	if (dVar3 == 1.0) break;
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
          	((basic_string *)local_68);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
          	((basic_string *)local_88);
	local_153 = uujfku(SUB81(local_88,0),SUB81(local_68,0));
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_88);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_68);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
          	((basic_string *)local_68);
	local_152 = nrxo(SUB81(local_68,0));
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_68);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
          	((basic_string *)local_68);
	local_151 = lpbnj(SUB81(local_68,0));
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_68);
	if (((local_153 != '\0') && (local_152 != '\0')) && (local_151 != '\0')) {
  	local_154 = '\x01';
  	break;
	}
	local_150 = local_150 + -1;
	std::__cxx11::to_string(local_a8,local_150);
	std::operator+((char *)local_88,(basic_string *)"You have ");
	std::operator+((basic_string *)local_68,(char *)local_88);
	pbVar2 = std::operator<<((basic_ostream *)std::cout,(basic_string *)local_68);
	std::basic_ostream<char,std::char_traits<char>>::operator<<
          	((basic_ostream<char,std::char_traits<char>> *)pbVar2,
           	std::endl<char,std::char_traits<char>>);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_68);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	(local_88);
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
          	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_a8);
  } while (local_150 != 0);
  if (local_154 == '\x01') {
	pbVar2 = std::operator<<((basic_ostream *)std::cout,
                         	"                                                                         	\n ________  ___  ___  ________  ________  _______   ________   _ _______  	\n|\\   ____\\|\\  \\|\\  \\|\\   ____\\|\\   ____\\|\\  _ __ \\ |\\   ____\\ |\\   ____\\ \n\\ \\  \\___|\\ \\  \\\\\\  \\ \\  \\ ___|\\ \\  \\___|\\ \\   __/|\\ \\  \\___|_\\ \\  \\___|_	\n \\ \\__ ___  \\ \\  \\\\\\  \\ \\  \\	\\ \\  \\	\\ \\  \\_|/_\\ \\_____   \\\\ \\_____  \\ \n  \\|____|\\  \\ \\  \\\\\\  \\ \\  \\____\\ \\  \\_ ___\\ \\  \\_|\\ \\|____|\\  \\\\|____|\\  \\ \n	____\\_\\  \\ \\___ ____\\ \\_______\\ \\_______\\ \\_______\\____\\_\\  \\ ____\\_\\  \\ \ n   |\\_________\\|_______|\\|_______|\\|_______|\\|_______|\\_________ \\\\_________\\\n   \\|_________|                                   	\\|_________\\|_________|\n                                                                                                                                                                                                                                        	\n    	"
                        	);
	std::operator<<(pbVar2,"\n\n");
	pbVar2 = std::operator<<((basic_ostream *)std::cout,"HERE\'S YOUR FLAG: CTF{5ecr3t_F14g_123456 }"
                        	);
	std::basic_ostream<char,std::char_traits<char>>::operator<<
          	((basic_ostream<char,std::char_traits<char>> *)pbVar2,
           	std::endl<char,std::char_traits<char>>);
  }
  else {
	pbVar2 = std::operator<<((basic_ostream *)std::cout,
                         	"                           	\n ________ ________  ___  ___   	__ _____   ________ 	\n|\\  _____\\\\   __  \\|\\  \\|\\  \\ 	|\\  _ __ \\ |\\   ___ \\ \n\\ \\  \\__/\\ \\  \\|\\  \\ \\  \\ \\  \\	\\ \ \   __/|\\ \\  \\_|\\ \\ \n \\ \\   __\\\\ \\   __  \\ \\  \\ \\  \\ 	\\ \\  \\_|/_\\ \\  \\ \\\\ \\ \n  \\ \\  \\_| \\ \\  \\ \\  \\ \\  \\  \\  \\____\\ \\  \\_|\\ \\ \\  \\_\\\\ \\ \n   \\ \\__\\   \\ \\__\\ \ \__\\ \\__\\ \\_______\\ \\_______\\ \\_______\\\n	\\|__|	\\|__|\ \|__|\\|__|\\|_______|\\|_______|\\|_______|                                                                                                                                                                                                         	\n    	"
                        	);
	std::operator<<(pbVar2,"\n\n");
  }
  pbVar2 = std::operator<<((basic_ostream *)std::cout,"EXITING VAULT TERMINAL... GOODBYE");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
        	((basic_ostream<char,std::char_traits<char>> *)pbVar2,
         	std::endl<char,std::char_traits<char>>);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_c8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_e8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_108);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_128);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
        	((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_148);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                	/* WARNING: Subroutine does not return */
	__stack_chk_fail();
  }
  return 0;
}