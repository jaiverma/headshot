//
//  trainer.cpp
//  Headshot
//
//  Created by Jai  Verma on 20/10/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#include "trainer.hpp"
#include "utils.hpp"

#include <cmath>
#include <chrono>
#include <thread>
#include <chrono>

Trainer::Trainer(int pid) {
    auto new_pid = static_cast<pid_t>(pid);
    this->pid = new_pid;
    task = task_from_pid(this->pid);
    constants = Constants();
    self = Player(constants.player_base_offset);
    
    auto player_count = read_data<uint32_t>(task, constants.enemy_count_addr);
    
    for (int i = 1; i < player_count; i++) {
        auto offset = std::vector<uintptr_t>{i * sizeof(uintptr_t)};
        auto enemy_addr = resolve_pointer_chain(task, constants.enemy_vector_addr, offset);
        enemies.push_back(Player(enemy_addr));
    }
}

void Trainer::reinit() {
    enemies.clear();
    auto player_count = read_data<uint32_t>(task, constants.enemy_count_addr);

    for (int i = 1; i < player_count; i++) {
        auto offset = std::vector<uintptr_t>{i * sizeof(uintptr_t)};
        auto enemy_addr = resolve_pointer_chain(task, constants.enemy_vector_addr, offset);
        enemies.push_back(Player(enemy_addr));
    }
}

float Trainer::get_distance(Player p, Player q) {
    auto position_p = p.get_position(task, "head");
    auto position_q = q.get_position(task, "head");

    auto p_x = std::get<0>(position_p);
    auto p_y = std::get<1>(position_p);

    auto q_x = std::get<0>(position_q);
    auto q_y = std::get<1>(position_q);

    auto dist = sqrt(pow(q_x - p_x, 2) + pow(q_y - p_y, 2));
    return dist;
}

std::tuple<float, float> Trainer::calc_aim_angles(Player p, Player q) {
    auto position_p = p.get_position(task, "head");
    auto position_q = q.get_position(task, "head");

    auto p_x = std::get<0>(position_p);
    auto p_y = std::get<1>(position_p);
    auto p_z = std::get<2>(position_p);

    auto q_x = std::get<0>(position_q);
    auto q_y = std::get<1>(position_q);
    auto q_z = std::get<2>(position_q);

    auto euclidean_dist = get_distance(p, q);

    auto pitch = -atan2(p_z - q_z, euclidean_dist) * 180 / M_PI;
    auto yaw = atan2(p_y - q_y, p_x - q_x) * 180 / M_PI;

    return std::make_tuple(pitch, yaw - 90);
}

char* Trainer::prepare_shellcode(uintptr_t code_addr) {
    char *shellcode = (char*)malloc(1024);
    memset(shellcode, 0, 1024);
    unsigned int i = 0;

    memcpy(shellcode + i, "\xb8\x70\x2a\x01\x00", 5); // mov eax, 0x12a70
    i += 5;

    memcpy(shellcode + i, "\xff\xd0", 2); // call eax
    i += 2;


    memcpy(shellcode + i, "\x90\x90", 2); // nop, nop
    i += 2;

    memcpy(shellcode + i, "\xb8", 2); // mov eax, code + i - 2
    i += 1;

    auto temp = pack_int(code_addr + i - 2);
    memcpy(shellcode + i, temp.c_str(), temp.length());
    i += temp.length();

    memcpy(shellcode + i, "\xff\xe0", 2); // jmp eax
    i += 2;

    return shellcode;
}

bool Trainer::trace_line(Player p, Player q) {
    auto position_p = p.get_position(task, "head");
    auto position_q = q.get_position(task, "head");

    struct traceresult_t {
        float x;
        float y;
        float z;
        bool collided;
    } traceresult;

    vm_address_t traceresult_addr = NULL;
    vm_address_t stack_addr = NULL;
    vm_address_t code_addr = NULL;
    mach_error_t error;
    vm_size_t stack_size = 1024; // 1 kB
    vm_size_t code_size = 1024;

    // allocate memory for traceresult_t in remote process
    error = vm_allocate(task, &traceresult_addr, sizeof(traceresult_t), 1);
    error = vm_protect(task, traceresult_addr, sizeof(traceresult_t), 0, VM_PROT_READ | VM_PROT_WRITE);

    // allocate stack
    error = vm_allocate(task, &stack_addr, stack_size, 1);
    error = vm_protect(task, stack_addr, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE);
    // since stack grows towards decreasing memory
    vm_address_t real_stack_addr = stack_addr + stack_size / 2;

    unsigned int n_param = 9;
    unsigned int stack_space = n_param * sizeof(uint32_t);
    char fake_stack[stack_space];

    // write function parameters to our constructed fake stack
    int i = 0;
    auto temp = pack_int(std::get<0>(position_p)); // p.x
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(std::get<1>(position_p)); // p.y
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(std::get<2>(position_p)); // p.z
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(std::get<0>(position_q)); // q.x
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(std::get<1>(position_q)); // q.y
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(std::get<2>(position_q)); // q.z
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(p.addr);
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(0);
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();
    temp = pack_int(traceresult_addr);
    memcpy(fake_stack + i, temp.c_str(), temp.length());
    i += temp.length();

    // write fake stack to remote process
    error = vm_write(task, real_stack_addr, (vm_offset_t)fake_stack, stack_space);

    // allocate .text
    error = vm_allocate(task, &code_addr, code_size, 1);

    // mark code segment as rwx
    error = vm_protect(task, code_addr, code_size, 0, VM_PROT_READ | VM_PROT_WRITE);

    char *shellcode = prepare_shellcode(code_addr);
    vm_write(task, code_addr, (vm_offset_t)shellcode, code_size);
    error = vm_protect(task, code_addr, code_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);

    i386_thread_state_t remote_thread_state;
    memset(&remote_thread_state, 0, sizeof(remote_thread_state));

    remote_thread_state.__eip = static_cast<uint32_t>(code_addr);
    remote_thread_state.__esp = static_cast<uint32_t>(real_stack_addr);
    remote_thread_state.__ebp = static_cast<uint32_t>(real_stack_addr);

    thread_act_t remote_thread;
    error = thread_create_running(task, i386_THREAD_STATE, (thread_state_t)&remote_thread_state, i386_THREAD_STATE_COUNT, &remote_thread);
    std::cerr << mach_error_string((kern_return_t)error) << std::endl;

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto collided = read_data<bool>(task, traceresult_addr + sizeof(float) * 3);
    thread_terminate(remote_thread);
    return (collided == 0);
}

void Trainer::menu() {
    std::cout << std::endl << "****************************" << std::endl;
    std::cout << "1. Set Health to 999" << std::endl;
    std::cout << "2. Set Clip to 999" << std::endl;
    std::cout << "3. Set Ammo to 999" << std::endl;
    std::cout << "4. Toggle Aimbot" << std::endl;
    std::cout << "****************************" << std::endl;
}

void Trainer::set_health(unsigned int health) {
    std::cout << "[*] Current health: " << self.get_health(task);
    std::cout << "[+] Overwriting with: " << health;
    self.set_health(task, health);
    std::cout << "[*] New health: " << self.get_health(task);
}

void Trainer::set_clip(unsigned int clip) {
    std::cout << "[*] Current clip: " << self.get_clip(task);
    std::cout << "[+] Overwriting with: " << clip;
    self.set_clip(task, clip);
    std::cout << "[*] New clip: " << self.get_clip(task);
}

void Trainer::set_ammo(unsigned int ammo) {
    std::cout << "[*] Current ammo: " << self.get_ammo(task);
    std::cout << "[+] Overwriting with: " << ammo;
    self.set_ammo(task, ammo);
    std::cout << "[*] New ammo: " << self.get_ammo(task);
}

void Trainer::aimbot() {
    auto start = std::chrono::high_resolution_clock::now();
    double duration;
    std::vector<float> pitchAngles(50);
    std::vector<float> yawAngles(50);
    unsigned int idx = 0;
    unsigned int cnt = 0;
    std::tuple<float, float> aim_angles;
    while (true) {
        reinit();
        std::vector<Player> alive_enemies;
        alive_enemies.clear();
        std::for_each(enemies.begin(), enemies.end(), [&](Player p) {
            if (p.is_alive(task))
                if (trace_line(self, p))
                    alive_enemies.push_back(p);
        });
        if (alive_enemies.size() > 0) {
            auto min = *std::min_element(alive_enemies.begin(), alive_enemies.end(), [&](Player p, Player q) {
                return get_distance(self, p) < get_distance(self, q);
                
            });
            aim_angles = calc_aim_angles(self, min);
            self.set_pitch(task, std::get<0>(aim_angles));
            self.set_yaw(task, std::get<1>(aim_angles));
        } else {
            aim_angles = std::make_tuple(self.get_pitch(task), self.get_yaw(task));
        }
        auto end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        if (duration >= 200) {
            std::cout << "adding to vector " << idx << std::endl;
            pitchAngles[idx] = std::get<0>(aim_angles);
            yawAngles[idx++] = std::get<1>(aim_angles);
            start = std::chrono::high_resolution_clock::now();
        }
        if (idx == 50) {
            std::cout << "\t\tWriting file\n";
            auto fileNamePitch = "/tmp/data/pitch_" + std::to_string(cnt) + ".raw";
            auto fileNameYaw = "/tmp/data/yaw_" + std::to_string(cnt++) + ".raw";
            saveTensorToFile(pitchAngles, fileNamePitch);
            saveTensorToFile(yawAngles, fileNameYaw);
            idx = 0;
        }
    }
}

void Trainer::handle_input() {
    unsigned int opt;
    std::cin >> opt;
    std::cout << opt << std::endl;
    
    switch (opt) {
        case 1:
            set_health(999);
            break;
        case 2:
            set_clip(999);
            break;
        case 3:
            set_ammo(999);
            break;
        case 4:
            aimbot();
            break;
        default:
            break;
    }
}
