//
//  mem.hpp
//  Headshot
//
//  Created by Jai  Verma on 26/08/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#ifndef mem_hpp
#define mem_hpp

#include <iostream>
#include <mach/mach.h>
#include <vector>

pid_t pid_from_name(std::string name);
task_t task_from_pid(pid_t pid);
uintptr_t resolve_pointer_chain(task_t task, uintptr_t start_ptr, std::vector<uintptr_t> offsets);

template <class T>
T read_data(task_t task, uintptr_t address) {
    kern_return_t kret;
    unsigned int count;
    vm_offset_t data_ptr = 0;
    
    kret = vm_read(task, (vm_address_t)address, sizeof(T), &data_ptr, &count);
    
    if (kret != KERN_SUCCESS) {
        std::cerr << "vm_read failed" << std::endl;
        std::cerr << mach_error_string(kret) << std::endl;
        exit(kret);
    }
    
    T dst;
    std::memcpy((void*)&dst, (void*)data_ptr, count);
    vm_deallocate(current_task(), data_ptr, count);

    return dst;
}

template <class T>
void write_data(task_t task, uintptr_t address, T src) {
    kern_return_t kret;
    
    kret = vm_write(task, (vm_address_t)address, (vm_offset_t)&src, sizeof(T));
    
    if (kret != KERN_SUCCESS) {
        std::cerr << "vm_write failed" << std::endl;
        std::cerr << mach_error_string(kret) << std::endl;
        exit(kret);
    }
}

template <class T>
std::string pack_int(T x) {    
    auto char_x = reinterpret_cast<char*>(&x);
    std::string packed;
    
    for (int i = 0; i < sizeof(T); i++)
        packed += char_x[i];
    
    return packed;
}

#endif /* mem_hpp */
