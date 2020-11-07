#pragma once
#include "Includes.h"

namespace settings {
	D3DXCOLOR FriendBox = D3DXCOLOR(0, 0, 1, 1);
	D3DXCOLOR EnemyBOX = D3DXCOLOR(1, 0, 0, 1);

	D3DXCOLOR FriendSkeleton = D3DXCOLOR(0, 0, 1, 1);
	D3DXCOLOR EnemySkeleton = D3DXCOLOR(1, 1, 0, 1);

	D3DXCOLOR FriendLine = D3DXCOLOR(0, 0, 1, 1);
	D3DXCOLOR EnemyLine = D3DXCOLOR(1, 0, 0, 1);

	D3DXCOLOR FriendFillbox = D3DXCOLOR(0, 0, 1, 1);
	D3DXCOLOR EnemyFillbox = D3DXCOLOR(1, 0, 0, 1);

	D3DXCOLOR Closed = D3DXCOLOR(1, 1, 0, 1);

	D3DXCOLOR boot = D3DXCOLOR(0, 0.5, 0.5, 1);

	bool teamBoxes = false;
	bool enemyBoxes = true;
	bool teamName = false;
	bool enemyName = false;
	bool teamDistance = false;
	bool enemyDistance = true;
	bool teamSnaplines = false;
	bool enemySnaplines = true;
	bool teamHealth = false;
	bool enemyHealth = true;
	bool teamFilledbox = false;
	bool enemyFilledbox = false;
	bool teamskeleton = false;
	bool enemyskeleton = false;

	bool aimbot = true;
	bool autolock = false;
	bool aimknocked = false;
	int aimbothitbox = 2;
	float aimspeed = 30;
	float aimbotfov = 9;
	float aimlock = 0.6;
	bool aimbotdrawfov = true;
	bool aimbotdrawhitbox = true;

	bool c_enable = true;
	int crosshair = 6;
	float size = 0;
	float stroke = 0;

	bool esp_Outline = 1;
	int boxtype = 0;
	int healthbartype = 0;
	float playersdis = 250;

	float menux = 0;
	float menuy = 400;

}
