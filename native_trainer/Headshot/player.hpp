//
//  player.hpp
//  Headshot
//
//  Created by Jai  Verma on 20/10/18.
//  Copyright © 2018 Jai  Verma. All rights reserved.
//

#ifndef player_hpp
#define player_hpp

#include "constants.hpp"
#include "mem.hpp"

class Player {
private:
    Constants constants;

public:
    uintptr_t addr;
    Player() = delete;
    Player(uintptr_t);
    unsigned int get_health(task_t);
    void set_health(task_t, unsigned int);
    unsigned int get_clip(task_t);
    void set_clip(task_t, unsigned int);
    unsigned int get_ammo(task_t);
    void set_ammo(task_t, unsigned int);
    float get_pitch(task_t);
    void set_pitch(task_t, float);
    float get_yaw(task_t);
    void set_yaw(task_t, float);
    bool is_alive(task_t);
    std::tuple<float, float, float> get_position(task_t, std::string);
};

#endif /* player_hpp */
