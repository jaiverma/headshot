//
//  constants.h
//  Headshot
//
//  Created by Jai  Verma on 16/09/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#ifndef constants_h
#define constants_h

#include <map>
#include <vector>
#include <string>

class Constants {
public:
    uintptr_t player_base_offset = 0x12b8a8;
    uintptr_t traceline_addr = 0x12a70;
    uintptr_t enemy_count_addr = player_base_offset + 0xc;
    uintptr_t enemy_vector_addr = player_base_offset + 0x4;
    std::vector<uintptr_t> health = { 0xf8 };
    std::vector<uintptr_t> weapon_ammo = { 0x374, 0x10, 0x0 };
    std::vector<uintptr_t> weapon_clip = { 0x374, 0x14, 0x0 };
    std::vector<uintptr_t> player_name = { 0x225 };
    std::vector<uintptr_t> head_vector3f = { 0x4 };
    std::vector<uintptr_t> foot_vector3f = { 0x34 };
    std::vector<uintptr_t> yaw = { 0x40 };
    std::vector<uintptr_t> pitch = { 0x44 };
    std::vector<uintptr_t> team = { 0x32c };
    std::map<std::string, std::vector<uintptr_t>> offsets;
    Constants();
};

#endif /* constants_h */
