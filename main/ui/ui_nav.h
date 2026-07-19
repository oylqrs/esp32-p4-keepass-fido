#pragma once

#include "lvgl.h"

typedef void (*ui_screen_show_cb_t)(void);

void ui_nav_push(ui_screen_show_cb_t current_screen, ui_screen_show_cb_t next_screen);
void ui_nav_go_back(void);
void ui_nav_enable_right_swipe(lv_obj_t *screen);
