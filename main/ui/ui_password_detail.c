#include "ui_password_detail.h"

#include <stdio.h>

#include "kdbx/kdbx_loader.h"
#include "lvgl.h"
#include "ui_nav.h"
#include "ui_password_manager.h"

#define PASSWORD_DETAIL_WIDTH 480

static size_t s_entry_index;

static void add_field(lv_obj_t *parent, const char *label_text, const char *value_text, bool password_mode)
{
    lv_obj_t *label = lv_label_create(parent);
    lv_label_set_text(label, label_text);
    lv_obj_set_style_text_color(label, lv_color_hex(0x9EA3AD), 0);
    lv_obj_set_style_text_font(label, &lv_font_montserrat_16, 0);

    lv_obj_t *value = lv_label_create(parent);
    lv_label_set_text(value, value_text && value_text[0] ? value_text : "-");
    lv_obj_set_width(value, PASSWORD_DETAIL_WIDTH - 64);
    lv_label_set_long_mode(value, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(value, password_mode ? lv_color_hex(0xFFC62E) : lv_color_white(), 0);
    lv_obj_set_style_text_font(value, &lv_font_montserrat_28, 0);
}

void ui_password_detail_show(void)
{
    const kdbx_entry_t *entry = kdbx_get_entry(s_entry_index);

    lv_obj_t *screen = lv_screen_active();
    lv_obj_clean(screen);
    ui_nav_enable_right_swipe(screen);
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x11141A), 0);
    lv_obj_set_style_pad_all(screen, 0, 0);

    lv_obj_t *title = lv_label_create(screen);
    lv_label_set_text(title, entry ? entry->title : "Password Detail");
    lv_obj_set_width(title, PASSWORD_DETAIL_WIDTH - 48);
    lv_label_set_long_mode(title, LV_LABEL_LONG_CLIP);
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_28, 0);
    lv_obj_align(title, LV_ALIGN_TOP_LEFT, 24, 38);

    lv_obj_t *panel = lv_obj_create(screen);
    lv_obj_remove_style_all(panel);
    lv_obj_set_size(panel, PASSWORD_DETAIL_WIDTH - 48, 560);
    lv_obj_align(panel, LV_ALIGN_TOP_MID, 0, 88);
    lv_obj_set_style_bg_color(panel, lv_color_hex(0x292A32), 0);
    lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(panel, 6, 0);
    lv_obj_set_style_pad_all(panel, 22, 0);
    lv_obj_set_flex_flow(panel, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(panel, 18, 0);
    lv_obj_add_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(panel, LV_DIR_VER);
    lv_obj_set_scrollbar_mode(panel, LV_SCROLLBAR_MODE_AUTO);

    if (!entry) {
        add_field(panel, "Error", "Entry not found", false);
        return;
    }

    add_field(panel, "Username", entry->username, false);
    add_field(panel, "URL", entry->url, false);
    add_field(panel, entry->password_protected ? "Password (protected)" : "Password", entry->password, true);
}

void ui_password_detail_open(size_t entry_index)
{
    ui_password_detail_set_entry(entry_index);
    ui_nav_push(ui_password_manager_show, ui_password_detail_show);
}

void ui_password_detail_set_entry(size_t entry_index)
{
    s_entry_index = entry_index;
}
