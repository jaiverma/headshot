//
//  player.cpp
//  Headshot
//
//  Created by Jai  Verma on 20/10/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#include "player.hpp"

Player::Player(uintptr_t addr) {
    this->addr = addr;
    constants = Constants();
}

unsigned int Player::get_health(task_t task) {
    auto health_addr = resolve_pointer_chain(task, addr, constants.offsets["health"]);
    if (health_addr < 0x1000)
        return 101;
    return read_data<uint32_t>(task, health_addr);
}

void Player::set_health(task_t task, unsigned int health) {
    auto health_addr = resolve_pointer_chain(task, addr, constants.offsets["health"]);
    auto new_health = static_cast<uint32_t>(health);
    write_data(task, health_addr, new_health);
}

unsigned int Player::get_clip(task_t task) {
    auto clip_addr = resolve_pointer_chain(task, addr, constants.offsets["weapon_clip"]);
    return read_data<uint32_t>(task, clip_addr);
}

void Player::set_clip(task_t task, unsigned int ammo) {
    auto clip_addr = resolve_pointer_chain(task, addr, constants.offsets["weapon_clip"]);
    auto new_clip = static_cast<uint32_t>(ammo);
    write_data(task, clip_addr, new_clip);
}

unsigned int Player::get_ammo(task_t task) {
    auto ammo_addr = resolve_pointer_chain(task, addr, constants.offsets["weapon_ammo"]);
    return read_data<uint32_t>(task, ammo_addr);
}

void Player::set_ammo(task_t task, unsigned int ammo) {
    auto ammo_addr = resolve_pointer_chain(task, addr, constants.offsets["weapon_ammo"]);
    auto new_ammo = static_cast<uint32_t>(ammo);
    write_data(task, ammo_addr, new_ammo);
}

float Player::get_pitch(task_t task) {
    auto pitch_addr = resolve_pointer_chain(task, addr, constants.offsets["pitch"]);
    return read_data<float>(task, pitch_addr);
}

void Player::set_pitch(task_t task, float pitch) {
    auto pitch_addr = resolve_pointer_chain(task, addr, constants.offsets["pitch"]);
    write_data(task, pitch_addr, pitch);
}

float Player::get_yaw(task_t task) {
    auto yaw_addr = resolve_pointer_chain(task, addr, constants.offsets["yaw"]);
    return read_data<float>(task, yaw_addr);
}

void Player::set_yaw(task_t task, float yaw) {
    auto yaw_addr = resolve_pointer_chain(task, addr, constants.offsets["yaw"]);
    write_data(task, yaw_addr, yaw);
}

bool Player::is_alive(task_t task) {
    unsigned int health = get_health(task);
    return (health <= 100);
}

std::tuple<float, float, float> Player::get_position(task_t task, std::string location) {
    uintptr_t position_addr = NULL;
    if (location == "head")
        position_addr = resolve_pointer_chain(task, addr, constants.offsets["head_vector3f"]);
    else // assume position to be foot
        position_addr = resolve_pointer_chain(task, addr, constants.offsets["foot_vector3f"]);
    
    auto x = read_data<float>(task, position_addr);
    auto y = read_data<float>(task, position_addr + sizeof(float));
    auto z = read_data<float>(task, position_addr + sizeof(float) * 2);
    
    return std::make_tuple(x, y, z);
}
