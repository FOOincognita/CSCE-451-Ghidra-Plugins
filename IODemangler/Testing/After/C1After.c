
undefined8 main(void) {
    basic_ostream *pbVar1;
    undefined8 uVar2;
    long in_FS_OFFSET;
    char local_8d;
    int local_8c;
    int local_88;
    int local_84;
    int local_80;
    int local_7c;
    int local_78;
    int local_74;
    int **local_70;
    basic_string local_68 [8];
    basic_string local_48 [10];
    long local_20;
    
    local_20 = *(long *)(in_FS_OFFSET + 0x28);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
    cout << "Please enter dungeon map file: ";
    cin >> (basic_istream *)std::cin,local_68;
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(local_48);
    local_70 = (int **)createMap((basic_string)local_48,&local_8c,&local_88,&local_84,&local_80);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_basic_string((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_48);
    if (local_70 == (int **)0x0) {
   	 std::operator<<((basic_ostream *)std::cout,"This dungeon map does not exist. ");
    cout << "Returning you back to the real word, adventurer!" << endl;
    uVar2 = 1;
    }
    else {
   	 cout << endl;
   	 cout << "---------------------------------------------------------" << endl;
   	 cout << "Good day, adventurer! Your goal is to escape the dungeon!" << endl;
   	 cout << " --- SYMBOLS ---" << endl;
   	 cout << " o      	: That is you, the adventurer!" << endl;
   	 cout << " x, -, |	: These are unpassable obstacles." << endl;
   	 cout << " !      	: That is the door to escape the dungeon." << endl;
   	 cout << " --- CONTROLS ---" << endl;
   	 cout << " w, a, s, d : Keys for moving up, left, down, and right." << endl;
   	 cout << " q      	: Key for abandoning your quest." << endl;
   	 cout << "---------------------------------------------------------" << endl;
   	 cout << endl;
   	 outputMap(local_70,local_8c,local_88);
   	 do {
   		 while( true ) {
   		 std::operator<<((basic_ostream *)std::cout,"Enter command (w,a,s,d: move, q: quit): ");
   		 cin >> local_8d;
   		 if (local_8d == 'q') {
   			 pbVar1 = std::operator<<((basic_ostream *)std::cout,"Thank you for playing!");
   			 cout << endl;
   			 goto LAB_001031ff;
   		 }
   		 if ((((local_8d == 'w') || (local_8d == 'a')) || (local_8d == 's')) || (local_8d == 'd'))
   			 break;
   		 cout << "I did not understand your command, adventurer!" << endl;
    }
    local_74 = updateNextPosition(local_70,&local_8c,&local_88,local_8d,&local_84,&local_80,&local_7c,&local_78);
    if ((local_74 == 0) || (local_74 == 2)) {
   	 updateMap(local_70,&local_84,&local_80,&local_7c,&local_78);
    }
    outputMap(local_70,local_8c,local_88);
    outputStatus(local_74,local_84,local_80);
    } while (local_74 != 2);
LAB_001031ff:
   	 deleteMap(local_70,local_8c);
   	 uVar2 = 0;
    }
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::_basic_string((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_68);
    if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
   	 return uVar2;
    }
                	/* WARNING: Subroutine does not return */
    __stack_chk_fail();
} 