//
//  mem.cpp
//  Headshot
//
//  Created by Jai  Verma on 26/08/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#include "mem.hpp"
#include <libproc.h>

pid_t pid_from_name(std::string name) {
    pid_t pids[1024];
    memset(pids, 0, sizeof(pids));
    proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    
    for (pid_t pid : pids) {
        if (pid) {
            char p_name[PROC_PIDPATHINFO_MAXSIZE];
            memset(p_name, 0, sizeof(p_name));
            proc_name(pid, p_name, sizeof(p_name));
            
            std::string proc_name(p_name);
            if (proc_name == name)
                return pid;
        }
    }
    return -1;
}

task_t task_from_pid(pid_t pid) {
    task_t task = 0;
    kern_return_t kret;
    
    kret = task_for_pid(current_task(), pid, &task);
    
    if (kret != KERN_SUCCESS) {
        std::cerr << "task_for_pid failed. are you root?" << std::endl;
        std::cerr << mach_error_string(kret) << std::endl;
        exit(-1);
    }
    
    return task;
}

uintptr_t resolve_pointer_chain(task_t task, uintptr_t start_ptr, std::vector<uintptr_t> offsets) {
    uintptr_t cur = start_ptr;
    uintptr_t cur_ptr = cur;
    for (uintptr_t offset : offsets) {
        cur_ptr = read_data<uintptr_t>(task, cur_ptr);
        cur_ptr += offset;
    }

    return cur_ptr;
}
