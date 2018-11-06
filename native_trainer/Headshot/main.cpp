//
//  main.cpp
//  Headshot
//
//  Created by Jai  Verma on 26/08/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#include <iostream>

#include "mem.hpp"
#include "constants.hpp"
#include "player.hpp"
#include "trainer.hpp"
#include <sstream>

int main(int argc, const char * argv[]) {
    pid_t pid = pid_from_name("assaultcube");
    std::cout << "pid of assaultcube " << pid << std::endl;
    
    Trainer t = Trainer(pid);
    
    while (true) {
        t.menu();
        t.handle_input();
    }
    
    return 0;
}
