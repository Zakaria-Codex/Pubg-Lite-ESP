#pragma once
#include <vector>
#include <time.h>
#include "Render.h"
#include "settings.h"
int get_frame_rate()
{
	static int i_fps, i_last_fps;
	static float fl_last_tick_count, fl_tick_count;
	fl_tick_count = clock() * 0.001f;
	i_fps++;
	if ((fl_tick_count - fl_last_tick_count) >= 1.0f)
	{
		fl_last_tick_count = fl_tick_count;
		i_last_fps = i_fps;
		i_fps = 0;
	}
	return i_last_fps;
};

class c_menu_framework
{
private:
public:
	float menu_x = 250, menu_y = 290;
	enum item_type : int {
		type_bool = 0,
		type_int = 1,
		type_float = 2
	};
	enum tab_type : int {
		type_on_off = 0,
		type_tab = 1,
		type_dont_draw = 2
	};
	static struct menu_item_t {
		std::string m_title;
		
		float* m_float;
		int* m_int;
		bool* m_bool = 0;
		int increment = 1;
		int minimum = 0;
		int maximum = 1;
		float m_float_step;
		int m_int_step;
		int m_type;
		int tab_type;

		float m_float_min;
		int m_int_min;

		float m_float_max;
		int m_int_max;

		std::string tool_tip;
	};

	//int m_total_items = 0;
	int m_current_pos = 0;
	int menu_page = 0;
	std::vector<menu_item_t> items;
public:

	void add_entry(std::string title, bool* value, int is_tab = 0, std::string tooltip = "") {
		menu_item_t m_item;
		m_item.m_title = title;
		m_item.m_bool = value;
		m_item.m_type = item_type::type_bool;
		m_item.tab_type = is_tab;
		m_item.tool_tip = tooltip;
		items.emplace_back(m_item);
	}

	template <class t>
	void add_entry(std::string title, t* value, t min, t max, t step) {
		menu_item_t m_item;
		m_item.m_title = title;
		if (std::is_same<t, float>()) {
			m_item.m_float = (float*)value;
			m_item.m_float_min = min;
			m_item.m_float_max = max;
			m_item.m_float_step = step;
			m_item.m_type = item_type::type_float;
		}
		else if (std::is_same<t, int>()) {
			m_item.m_int = (int*)value;
			m_item.m_int_min = min;
			m_item.m_int_max = max;
			m_item.m_int_step = step;
			m_item.m_type = item_type::type_int;
		}
		items.emplace_back(m_item);
	}

	void draw()
	{
		this->menu_x = settings::menux;
		this->menu_y = settings::menuy;

		static bool aimbot_tap = false;
		static bool espteam_tap = false;
		static bool espenemy_tab = false;
		static bool color_tab = false;
		static bool misc_tab = false;
		static bool menu_tab = false;
		static bool crosshair_tab = false;

		this->add_entry("AIMBOT", &aimbot_tap, true,"This Option I Thing No Safe");
		if (aimbot_tap) {
			this->add_entry("  Active", &settings::aimbot);
			this->add_entry("  Auto Lock", &settings::autolock);
			this->add_entry("  Aim Knocked", &settings::aimknocked);
			this->add_entry("  Hitbox", &settings::aimbothitbox, 0,2, 1);
			this->add_entry("  Fov", &settings::aimbotfov, 1.f, 100.f, 1.f);
			this->add_entry("  Speed", &settings::aimspeed, 1.f, 100.f, 1.f);
			this->add_entry("  Lock", &settings::aimlock, 0.f, 20.f, 0.1f);
			this->add_entry("  Draw Hitbox", &settings::aimbotdrawhitbox);
			this->add_entry("  Draw Fov", &settings::aimbotdrawfov);

		}

		this->add_entry("TEAM ESP", &espteam_tap, true);
		if (espteam_tap) {
			this->add_entry("  Boxes", &settings::teamBoxes);
			this->add_entry("  Name", &settings::teamName);
			this->add_entry("  Snaplines", &settings::teamSnaplines);
			this->add_entry("  Healthbars", &settings::teamHealth);
			this->add_entry("  Distance", &settings::teamDistance);
			this->add_entry("  FilledBox", &settings::teamFilledbox);
			this->add_entry("  Skeleton", &settings::teamskeleton);

		}

		this->add_entry("ENEMY ESP", &espenemy_tab, true);
		if (espenemy_tab) {
			this->add_entry("  Boxes", &settings::enemyBoxes);
			this->add_entry("  Name", &settings::enemyName);
			this->add_entry("  Snaplines", &settings::enemySnaplines);
			this->add_entry("  Healthbars", &settings::enemyHealth);
			this->add_entry("  Distance", &settings::enemyDistance);
			this->add_entry("  FilledBox", &settings::enemyFilledbox);
			this->add_entry("  Skeleton", &settings::enemyskeleton);

		}
		this->add_entry("CROSSHAIR", &crosshair_tab, true);
		if (crosshair_tab) {
			this->add_entry("  Enable", &settings::c_enable);
			this->add_entry("  Crosshair Style", &settings::crosshair, 0, 4, 1);
			this->add_entry("  Size", &settings::size, 1.f, 20.f, 1.f);
			this->add_entry("  Stroke", &settings::stroke, 1.f, 10.f, 1.f);

		}
		this->add_entry("SETTINGS ESP", &misc_tab, true);
		if (misc_tab) {
			this->add_entry("  ESP Outline", &settings::esp_Outline);
			this->add_entry("  Box Type", &settings::boxtype, 0, 1, 1);
			this->add_entry("  HealthBar Type", &settings::healthbartype, 0, 2, 1);
			this->add_entry("  Players Distance", &settings::playersdis, 1.f, 700.f, 20.f);


		}
		static bool colorteam_tab = false;
		this->add_entry("COLORS", &color_tab, true);
		if (color_tab) {
			static bool colorteambox_tab = false;
			this->add_entry("  Team Box", &colorteambox_tab, true);
			if (colorteambox_tab) {
				static auto prim_r = 0.f, prim_g = 0.f, prim_b = 255.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::FriendBox = D3DXCOLOR(prim_r/ 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);


			}

			static bool colorteamline_tab = false;
			this->add_entry("  Team Line", &colorteamline_tab, true);
			if (colorteamline_tab) {
				static auto prim_r = 0.f, prim_g = 0.f, prim_b = 255.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::FriendLine = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}
			static bool colorteamfillbox_tab = false;
			this->add_entry("  Team FillBox", &colorteamfillbox_tab, true);
			if (colorteamfillbox_tab) {
				static auto prim_r = 0.f, prim_g = 0.f, prim_b = 255.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::FriendFillbox = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}

			static bool colorteamskeleton_tab = false;
			this->add_entry("  Team skeleton", &colorteamskeleton_tab, true);
			if (colorteamskeleton_tab) {
				static auto prim_r = 0.f, prim_g = 0.f, prim_b = 255.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::FriendSkeleton = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}

			static bool colortenemybox_tab = false;
			this->add_entry("  Enemy Box", &colortenemybox_tab, true);
			if (colortenemybox_tab) {
				static auto prim_r = 255.f, prim_g = 0.f, prim_b = 0.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::EnemyBOX = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}

			static bool colortenemyline_tab = false;
			this->add_entry("  Enemy Line", &colortenemyline_tab, true);
			if (colortenemyline_tab) {
				static auto prim_r = 255.f, prim_g = 0.f, prim_b = 0.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::EnemyLine = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}

			static bool colortenemyfillbox_tab = false;
			this->add_entry("  Enemy Fillbox", &colortenemyfillbox_tab, true);
			if (colortenemyfillbox_tab) {
				static auto prim_r = 255.f, prim_g = 0.f, prim_b = 0.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::EnemyFillbox = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}

			static bool colortenemyskeleton_tab = false;
			this->add_entry("  Enemy Skeleton", &colortenemyskeleton_tab, true);
			if (colortenemyskeleton_tab) {
				static auto prim_r = 255.f, prim_g = 255.f, prim_b = 0.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::EnemySkeleton = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}
			static bool colorclosed_tab = false;
			this->add_entry("  CLOSED", &colorclosed_tab, true);
			if (colorclosed_tab) {
				static auto prim_r = 255.f, prim_g = 255.f, prim_b = 0.f;
				this->add_entry("    Primary Red", &prim_r, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Green", &prim_g, 0.f, 255.f, 20.f);
				this->add_entry("    Primary Blue", &prim_b, 0.f, 255.f, 20.f);
				settings::Closed = D3DXCOLOR(prim_r / 255.0f, prim_g / 255.0f, prim_b / 255.0f, 1.f);

			}


		}

		this->add_entry("MENU", &menu_tab, true);
		if (menu_tab) {
			this->add_entry("  Menu x", &settings::menux, 0.f, 2560.f, 50.f);
			this->add_entry("  Menu y", &settings::menuy, 0.f, 1440.f, 50.f);

		}

	}
	 time_t lastTime;
	bool ReadKeyOnce(unsigned int keycode, unsigned int timer) {
		if ((clock() - lastTime > timer) && GetAsyncKeyState(keycode)) {
			lastTime = clock();
			return true;
		}
		return false;
	}
	void do_menu_controls() {
		static bool show = true;
		if (show) {
			this->draw();
			static int item_gap = 14;
			static float alpha = 1.f;
			DrawBox(this->menu_x - 3, this->menu_y - 17, 154, 17, 1.f, 0.10f, 0.10f, 0.10f, alpha, true);
			DrawBox(this->menu_x - 3, this->menu_y - 17, 154, 17, 1.f, 0.4f, 0, 0.8f, alpha, false);

			DrawString("Exit/Hide End/Ins - " + std::to_string(get_frame_rate()), 12, this->menu_x + 9, this->menu_y - 18, 1.f, 1.f, 1.f, alpha);

			DrawBox(this->menu_x - 3, this->menu_y, 154, (items.size() * item_gap), 1.f, 0.12f, 0.12f, 0.12f, alpha, true);
			DrawBox(this->menu_x - 3, this->menu_y, 154, (items.size() * item_gap), 1.f, 0.4f, 0, 0.8f, alpha, false);

			DrawBox(this->menu_x - 3, this->menu_y + (item_gap * m_current_pos), 154, item_gap, 1.f, 0.10f, 0.10f, 0.10f, alpha, true);
			DrawBox(this->menu_x - 3, this->menu_y + (item_gap * m_current_pos), 154, item_gap, 1.f, 0.4f, 0, 0.8f, alpha, false);

			if (items.empty())
				return;
			if (m_current_pos > items.size())
				m_current_pos = items.size();

			if (!items[m_current_pos].tool_tip.empty()) {
				DrawBox(this->menu_x - 3, this->menu_y + (items.size() * item_gap) + 3, 154, 28, 1.0, 0.12f, 0.12f, 0.12f, alpha, true);
				DrawBox(this->menu_x - 3, this->menu_y + (items.size() * item_gap) + 3, 154, 28, 1.0, 0.4, 0.f, 0.8f, alpha, false);

				DrawString("NOTE:", 12, this->menu_x, this->menu_y + (items.size() * item_gap) + 5, 1, 1, 1, alpha);
				DrawString(items[m_current_pos].tool_tip.c_str(), 11, this->menu_x, this->menu_y + (items.size() * item_gap) + 16, 1, 1, 1, alpha);

			}

			for (auto item = 0; item < items.size(); ++item) {
				auto height = this->menu_y + (item_gap * item);
				char txt[1024];
				switch (items[item].m_type)
				{
				case item_type::type_bool: {
					D3DXCOLOR _bool = *items[item].m_bool ? D3DXCOLOR(0, 1.f, 0, alpha) : D3DXCOLOR(1.f, 0, 0, alpha);

					DrawString(items[item].m_title.c_str(), 12, this->menu_x, height, 1, 1, 1, alpha);
					if (items[item].tab_type == tab_type::type_on_off)
						DrawString(*items[item].m_bool ? "ON" : "OFF", 11, this->menu_x + 130, height, _bool.r, _bool.g, _bool.b, _bool.a);
					else if (items[item].tab_type == tab_type::type_tab)
						DrawString(*items[item].m_bool ? "[-]" : "[+]", 11, this->menu_x + 130, height, _bool.r, _bool.g, _bool.b, _bool.a);
					break;
				}
				case item_type::type_int: {
					DrawString(items[item].m_title.c_str(), 11, this->menu_x, height, 1, 1, 1, alpha);
					sprintf(txt, "%i", *items[item].m_int);
					DrawString(txt, 11, this->menu_x + 130, height, 1, 1, 1, alpha);
					break;
				}
				case item_type::type_float: {
					DrawString(items[item].m_title.c_str(), 11, this->menu_x, height, 1.f, 1.f, 1.f, alpha);
					sprintf(txt, "%.1f", *items[item].m_float);
					DrawString(txt, 11, this->menu_x + 130, height, 1, 1, 1, alpha);
					break;
				}
				default:
					break;
				}

				if (ReadKeyOnce(VK_UP,250)) {
					this->m_current_pos -= 1;
					if (this->m_current_pos < 0)
						m_current_pos = (m_current_pos > 0) ? (m_current_pos - 1) : items.size() - 1;
				}
				if (ReadKeyOnce(VK_DOWN,250)) {
					this->m_current_pos += 1;
					if (this->m_current_pos > items.size() - 1)
						this->m_current_pos = 0;
				}

				if (ReadKeyOnce(VK_LEFT, 250)) {
					switch (items[m_current_pos].m_type) {
					case item_type::type_bool: {
						if (*items[m_current_pos].m_bool == 1) {
							*items[m_current_pos].m_bool -= items[m_current_pos].increment;
							if (*items[m_current_pos].m_bool < items[m_current_pos].minimum)
								*items[m_current_pos].m_bool = items[m_current_pos].minimum;
						}
						break;
					}
					case item_type::type_int: {

						*items[m_current_pos].m_int -= items[m_current_pos].m_int_step;
						if (*items[m_current_pos].m_int < items[m_current_pos].m_int_min)
							*items[m_current_pos].m_int = items[m_current_pos].m_int_max;
						break;
					}
					case item_type::type_float: {
						*items[m_current_pos].m_float -= items[m_current_pos].m_float_step;
						if (*items[m_current_pos].m_float < items[m_current_pos].m_float_min)
							*items[m_current_pos].m_float = items[m_current_pos].m_float_max;
						break;
					}
					default:
						break;
					}

				}
				if (ReadKeyOnce(VK_RIGHT, 250)) {
					switch (items[m_current_pos].m_type) {
					case item_type::type_bool: {
						if (*items[m_current_pos].m_bool == 0) {
							*items[m_current_pos].m_bool += items[m_current_pos].increment;
							if (*items[m_current_pos].m_bool > items[m_current_pos].maximum)
								//*items[m_current_pos].m_bool = !*items[m_current_pos].m_bool;
								*items[m_current_pos].m_bool = items[m_current_pos].maximum;
						}
						break;
					}
					case item_type::type_int: {
						*items[m_current_pos].m_int += items[m_current_pos].m_int_step;
						if (*items[m_current_pos].m_int > items[m_current_pos].m_int_max)
							*items[m_current_pos].m_int = items[m_current_pos].m_int_min;
						break;
					}
					case item_type::type_float: {
						*items[m_current_pos].m_float += items[m_current_pos].m_float_step;
						if (*items[m_current_pos].m_float > items[m_current_pos].m_float_max)
							*items[m_current_pos].m_float = items[m_current_pos].m_float_min;
						break;
					}
					default:
						break;
					}


				}
			}
		}
		if (!items.empty())
			items.clear();
		if (GetAsyncKeyState(VK_INSERT)) {
			show = !show;
			Sleep(150);
		}
		if (GetAsyncKeyState(VK_END))
			exit(0);
	}

};


