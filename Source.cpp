#include "SDK.h"
#include "Menu.h"
#include <list>
#define checkSetting(teamval, enemyval) (((gm.LocalPlayer.Team == player.Team) && teamval) || ((gm.LocalPlayer.Team != player.Team) && enemyval))
#define pasteColor(x) x.r, x.g, x.b
#define pasteColorA(x) x.r, x.g, x.b, x.a
LPCSTR FilePath = "./Settings.ini";

c_menu_framework* menu_framework = new c_menu_framework;

std::vector<uint64> Players;

static class Text
{
public:
	std::string text;
	int side;
	int size;
	D3DXCOLOR color;
	Text(std::string text, int side, int size, D3DXCOLOR color) : text(text), side(side), size(size), color(color) {}
};

void ShellTaskmanager()
{
	ITaskbarList* pTaskList = NULL;
	HRESULT initRet = CoInitialize(NULL);
	HRESULT createRet = CoCreateInstance(CLSID_TaskbarList,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskbarList,
		(LPVOID*)&pTaskList);

	if (createRet == S_OK)
	{

		pTaskList->DeleteTab(GetConsoleWindow());

		pTaskList->Release();
	}

	CoUninitialize();
}
void Crosshair()
{
	switch (settings::crosshair)
	{
	case Renderer::CrosshairStyle::Dot:
		Renderer::GetInstance()->DrawCrosshair(Renderer::CrosshairStyle::Dot, S_width / 2, S_height / 2, settings::size, settings::stroke, D3DXCOLOR(0.f, 1.f, 0.f, 1.f));
		break;
	case Renderer::CrosshairStyle::Plus:
		Renderer::GetInstance()->DrawCrosshair(Renderer::CrosshairStyle::Plus, S_width / 2, S_height / 2, settings::size, settings::stroke, D3DXCOLOR(0.f, 1.f, 0.f, 1.f));
		break;
	case Renderer::CrosshairStyle::Cross:
		Renderer::GetInstance()->DrawCrosshair(Renderer::CrosshairStyle::Cross, S_width / 2, S_height / 2, settings::size, settings::stroke, D3DXCOLOR(0.f, 1.f, 0.f, 1.f));
		break;
	case Renderer::CrosshairStyle::Gap:
		Renderer::GetInstance()->DrawCrosshair(Renderer::CrosshairStyle::Gap, S_width / 2, S_height / 2, settings::size, settings::stroke, D3DXCOLOR(0.f, 1.f, 0.f, 1.f));
		break;
	case Renderer::CrosshairStyle::Diagonal:
		Renderer::GetInstance()->DrawCrosshair(Renderer::CrosshairStyle::Diagonal, S_width / 2, S_height / 2, settings::size, settings::stroke, D3DXCOLOR(0.f, 1.f, 0.f, 1.f));
		break;
	default:
		break;
	}
}
DWORD WINAPI TIMER(LPVOID p)
{

	while (true)
	{
		dwUWorld = rpm.read<uint64>(GameModule + UWorld);
		ULevel = Decrypt::ULevelDec(Ulevel);//0xB80
		ActorArray = Decrypt::DecryptActors(rpm.read<uint64>(ULevel + actorArray));
		for (size_t i = 0; i < 1400; i++)
		{
			uint64 Entity = rpm.read<uint64>(rpm.read<uint64>(ActorArray) + i * 0x8);
			uint64 objectID = Decrypt::ObjID(rpm.read<uint64>(Entity + 0xC));
			std::string ObjectName = Decrypt::GetGNamesByObjID(objectID);

			if (ObjectName == "BP_PlayerRifleBulletImpact_C")
				continue;

			if (ObjectName.find("BP_Player") != 0)
				continue;

			Players.push_back(Entity);
		}
		for (int i = 0; i < 1400; i++)
			Paddr[i] = 0;
		PlayerNum = Players.size();
		for (int i = 0; i < PlayerNum; i++)
			Paddr[i] = Players[i];
		
		Players.clear();
	}
	return 1;
}
void DrawSkeleton(Player pPlayer, Manager GM, D3DXCOLOR clr)
{
	std::list<int> upper_part = { EBoneIndex::neck_01, EBoneIndex::Head };
	std::list<int> right_arm = { EBoneIndex::neck_01, EBoneIndex::upperarm_r, EBoneIndex::lowerarm_r, EBoneIndex::hand_r };
	std::list<int> left_arm = { EBoneIndex::neck_01, EBoneIndex::upperarm_l, EBoneIndex::lowerarm_l, EBoneIndex::hand_l };
	std::list<int> spine = { EBoneIndex::neck_01, EBoneIndex::spine_01, EBoneIndex::spine_02, EBoneIndex::pelvis };
	std::list<int> lower_right = { EBoneIndex::pelvis, EBoneIndex::thigh_r, EBoneIndex::calf_r, EBoneIndex::foot_r };
	std::list<int> lower_left = { EBoneIndex::pelvis, EBoneIndex::thigh_l, EBoneIndex::calf_l, EBoneIndex::foot_l };
	std::list<std::list<int>> skeleton = { upper_part, right_arm, left_arm, spine, lower_right, lower_left };

	FVector neckpos = pPlayer.GetBoneWithRotation( EBoneIndex::neck_01);
	FVector pelvispos = pPlayer.GetBoneWithRotation( EBoneIndex::pelvis);
	FVector previous(0, 0, 0);
	FVector current, p1, c1;

	for (auto a : skeleton)
	{
		previous = FVector(0, 0, 0);

		for (int bone : a)
		{
			current = bone == EBoneIndex::neck_01 ? neckpos : (bone == EBoneIndex::pelvis ? pelvispos : pPlayer.GetBoneWithRotation(bone));
			if (previous.X == 0.f)
			{
				previous = current;
				continue;
			}
			p1 = GM.WorldToScreen( previous);
			c1 = GM.WorldToScreen( current);

			DrawLine(p1.X, p1.Y, c1.X, c1.Y,1, pasteColor(clr));
			previous = current;
		}
	}
}
void CoutOffset(LPCSTR name, DWORD offset)
{
	std::cout << "[" << name << "]" << " = 0x" << std::uppercase << std::hex << offset << std::endl;
}
void Coutfloat(LPCSTR name, float option)
{
	std::cout << "[" << name << "]" << " = " << std::dec << option << std::endl;
}

void Coutbool(LPCSTR name, int boolean)
{
	if (boolean == 1)
		std::cout << "[" << name << "]" << " = " << "ON" << std::endl;
	else
		std::cout << "[" << name << "]" << " = " << "OFF" << std::endl;
}
float ReadConfig(LPCSTR Option, bool Float)
{
	if (Float)
	{
		char cfg[10];
		GetPrivateProfileString(TEXT("Config"), Option, TEXT("0"), cfg, 10, FilePath);
		float opt = atof(cfg);
		return opt;
	}
	else
		return GetPrivateProfileInt(TEXT("Config"), Option, NULL, FilePath);
}
DWORD ReadInt(LPCTSTR Offsetname)
{
	DWORD Offset = GetPrivateProfileInt(TEXT("Offsets"), Offsetname, NULL, FilePath);
	CoutOffset(Offsetname, Offset);
	return Offset;
}
void ReadSettings()
{
	settings::aimbot = ReadConfig(TEXT("Active"), false);
	settings::autolock = ReadConfig(TEXT("AutoLock"), false);
	settings::aimknocked = ReadConfig(TEXT("AimKnocket"), false);
	settings::aimbothitbox = ReadConfig(TEXT("HitBox"), true);
	settings::aimspeed = ReadConfig(TEXT("AimSpeed"), true);
	settings::aimbotfov = ReadConfig(TEXT("Fov"), true);
	settings::aimlock = ReadConfig(TEXT("aimlock"), true);

	settings::aimbotdrawfov = ReadConfig(TEXT("DrawFov"), false);
	settings::aimbotdrawhitbox = ReadConfig(TEXT("DrawHitBox"), false);

	settings::teamBoxes = ReadConfig(TEXT("TeamBox"), false);
	settings::teamDistance = ReadConfig(TEXT("TeamDistance"), false);
	settings::teamSnaplines = ReadConfig(TEXT("TeamSnaplines"), false);
	settings::teamHealth = ReadConfig(TEXT("TeamHealth"), false);
	settings::teamFilledbox = ReadConfig(TEXT("TeamFilledbox"), false);
	settings::teamskeleton = ReadConfig(TEXT("TeamSkeleton"), false);

	settings::enemyBoxes = ReadConfig(TEXT("EnemyBoxes"), false);
	settings::enemyDistance = ReadConfig(TEXT("EnemyDistance"), false);
	settings::enemySnaplines = ReadConfig(TEXT("EnemySnaplines"), false);
	settings::enemyHealth = ReadConfig(TEXT("EnemyHealth"), false);
	settings::enemyFilledbox = ReadConfig(TEXT("EnemyFilledbox"), false);
	settings::enemyskeleton = ReadConfig(TEXT("EnemySkeleton"), false);

	settings::c_enable = ReadConfig(TEXT("CrosshairEnable"), false);
	settings::crosshair = ReadConfig(TEXT("CrosshairStyle"), true);
	settings::size = ReadConfig(TEXT("Size"), true);
	settings::stroke = ReadConfig(TEXT("Stroke"), true);

	settings::esp_Outline = ReadConfig(TEXT("Outline"), false);
	settings::boxtype = ReadConfig(TEXT("BoxType"), true);
	settings::healthbartype = ReadConfig(TEXT("HealthbarType"), true);
	settings::playersdis = ReadConfig(TEXT("PlayersDis"), true);

	settings::menux = ReadConfig(TEXT("MenuX"), true);
	settings::menuy = ReadConfig(TEXT("MenuY"), true);

	std::cout << std::endl << std::endl;
	std::cout << "AIMBOT" << std::endl << std::endl;
	Coutbool(TEXT("Active"), settings::aimbot);
	Coutbool(TEXT("AutoLock"), settings::autolock);
	Coutbool(TEXT("AimKnocket"), settings::aimknocked);
	Coutfloat(TEXT("HitBox"), settings::aimbothitbox);
	Coutfloat(TEXT("AimSpeed"), settings::aimspeed);
	Coutfloat(TEXT("Fov"), settings::aimbotfov);
	Coutfloat(TEXT("Lock"), settings::aimlock);
	Coutbool(TEXT("DrawFov"), settings::aimbotdrawfov);
	Coutbool(TEXT("DrawHitBox"), settings::aimbotdrawhitbox);

	std::cout << std::endl << std::endl;
	std::cout << "TEAM ESP" << std::endl << std::endl;
	Coutbool(TEXT("Box"), settings::teamBoxes);
	Coutbool(TEXT("Distance"), settings::teamDistance);
	Coutbool(TEXT("Snaplines"), settings::teamSnaplines);
	Coutbool(TEXT("Health"), settings::teamHealth);
	Coutbool(TEXT("Filledbox"), settings::teamFilledbox);
	Coutbool(TEXT("TeamSkeleton"), settings::teamskeleton);

	std::cout << std::endl << std::endl;
	std::cout << "ENEMY ESP" << std::endl << std::endl;
	Coutbool(TEXT("Box"), settings::enemyBoxes);
	Coutbool(TEXT("Distance"), settings::enemyDistance);
	Coutbool(TEXT("Snaplines"), settings::enemySnaplines);
	Coutbool(TEXT("Health"), settings::enemyHealth);
	Coutbool(TEXT("Filledbox"), settings::enemyFilledbox);
	Coutbool(TEXT("EnemySkeleton"), settings::enemyskeleton);

	std::cout << std::endl << std::endl;
	std::cout << "CROSSHAIR" << std::endl << std::endl;
	Coutbool(TEXT("CrosshairEnable"), settings::c_enable);
	Coutfloat(TEXT("CrosshairStyle"), settings::crosshair);
	Coutfloat(TEXT("Size"), settings::size);
	Coutfloat(TEXT("stroke"), settings::stroke);

	std::cout << std::endl << std::endl;
	std::cout << "SETTINGS ESP" << std::endl << std::endl;
	Coutbool(TEXT("Outline"), settings::esp_Outline);
	Coutfloat(TEXT("BoxType"), settings::boxtype);
	Coutfloat(TEXT("HealthbarType"), settings::healthbartype);
	Coutfloat(TEXT("PlayersDis"), settings::healthbartype);

	std::cout << std::endl << std::endl;
	std::cout << "MENU" << std::endl << std::endl;
	Coutfloat(TEXT("MenuX"), settings::menux);
	Coutfloat(TEXT("MenuY"), settings::menuy);
	std::cout << std::endl << std::endl;
}

void drawLoop(int width, int height)
{

	menu_framework->do_menu_controls();
	if (settings::c_enable)
		Crosshair();

	Manager gm(width, height);
	for (Player& player : gm.Players) {
		FVector footLocation = player.Location;
		FVector headLocation = player.Head;
		FVector ofootLocation;
		FVector oheadLocation;
		D3DXCOLOR PlayerBox = D3DXCOLOR();
		D3DXCOLOR PlayerLine = D3DXCOLOR();
		D3DXCOLOR PlayerFillBox = D3DXCOLOR();
		D3DXCOLOR PlayerSkeleton = D3DXCOLOR();

		if (player.Team == gm.LocalPlayer.Team) {
			PlayerBox = settings::FriendBox;
			PlayerLine = settings::FriendLine;
			PlayerFillBox = settings::FriendFillbox;
			PlayerSkeleton = settings::FriendSkeleton;

		}
		else {
			if (player.Distance < 80) {

				PlayerBox = settings::Closed;
				PlayerLine = settings::Closed;
				PlayerFillBox = settings::Closed;
				PlayerSkeleton = settings::Closed;

			}
			else {
				PlayerBox = settings::EnemyBOX;
				PlayerLine = settings::EnemyLine;
				PlayerFillBox = settings::EnemyFillbox;
				PlayerSkeleton = settings::EnemySkeleton;

			}
		}
		if (player.Team != gm.LocalPlayer.Team) {

			if (gm.ClosestVisibleEnemy.Distance < 80)
			{
				DrawBox((S_width / 2) - 30, 170, 220, 50, 1, 0, 0, 0, 0.5, true);
				DrawString("Enemy Closed " + std::to_string((int)gm.ClosestVisibleEnemy.Distance) + "m", 20, S_width / 2, 180, 1.f, 0.f, 0.f, 1.f);
			}

		}
		ofootLocation = gm.WorldToScreen(footLocation);
		oheadLocation = gm.WorldToScreen( headLocation);
		float w2sHeight = Distance3D(ofootLocation, oheadLocation);
		float w2sWidth = w2sHeight;
		float heightoffset = Distance3D(ofootLocation, oheadLocation);
		float H = w2sHeight;
		float W = H / 2;
		float X = oheadLocation.X - W / 2;
		std::vector< Text > texts;

		if (player.Distance > settings::playersdis) continue;
		if (player.IsAbot)
		{
			PlayerBox = settings::boot;
			PlayerLine = settings::boot;
			PlayerFillBox = settings::boot;

		}
		else
		{
			if checkSetting(settings::teamSnaplines, settings::enemySnaplines) {
				DrawLine(S_width / 2, 0, oheadLocation.X, oheadLocation.Y, 1, pasteColorA(PlayerLine));
			}
			if checkSetting(settings::teamBoxes, settings::enemyBoxes) {
				if (settings::boxtype == 0)
				{
					if (!settings::esp_Outline)
						DrawBox(X, oheadLocation.Y, W, H, 2.f, pasteColorA(PlayerBox), false);
					else if (settings::esp_Outline)
						Renderer::GetInstance()->DrawOutlineBox(X, oheadLocation.Y, W, H, PlayerBox, 2.f);

				}
				else
				{
					if (!settings::esp_Outline)
						Renderer::GetInstance()->DrawCoalBox(X, oheadLocation.Y, W, H, PlayerBox, 2.f);
					else if (settings::esp_Outline)
						Renderer::GetInstance()->DrawOutlineCoalBox(X, oheadLocation.Y, W, H, PlayerBox, 2.f);

				}
			}

			if checkSetting(settings::teamFilledbox, settings::enemyFilledbox) {
				DrawBox(X, oheadLocation.Y, W, H, 1, pasteColor(PlayerFillBox), 0.1, true);

			}

			if checkSetting(settings::teamskeleton, settings::enemyskeleton) {
				DrawSkeleton(player, gm, PlayerSkeleton);
			}
			if checkSetting(settings::teamHealth, settings::enemyHealth) {
				if (settings::healthbartype == 0)
					Renderer::GetInstance()->DrawHorBar(X, oheadLocation.Y - 6, W, 4, (int)player.Health, 120, D3DXCOLOR(.48f, .98f, 0.f, 1.f), D3DXCOLOR(1.f, 0.f, 0.f, 1.f));
				else if (settings::healthbartype == 1)
					Renderer::GetInstance()->DrawVerBar(X - 6, oheadLocation.Y, 4, H, (int)player.Health, 120, D3DXCOLOR(.48f, .98f, 0.f, 1.f), D3DXCOLOR(1.f, 0.f, 0.f, 1.f));
				else
					texts.push_back(Text("Health " + std::to_string((int)player.Health) + "%", 2, 9, D3DXCOLOR(.48f, .98f, 0.f, 1.f)));

			}

			if checkSetting(settings::teamDistance, settings::enemyDistance) {

				texts.push_back(Text(std::to_string((int)player.Distance) + "m", 1, 9, D3DXCOLOR(1.f, 1.f, 1.f, 1.f)));
			}
			if checkSetting(settings::teamName, settings::enemyName) {

				texts.push_back(Text(player.Name(), 0, 9, D3DXCOLOR(1.f, 1.f, 1.f, 1.f)));
			}
		}
		int middle[3] = { ofootLocation.Y,ofootLocation.Y, ofootLocation.X - ofootLocation.Y };
		int Top[3] = { oheadLocation.Y,oheadLocation.X, oheadLocation.X - oheadLocation.Y };
		for (auto text : texts)
		{
			int fontsize = text.size;
			float offset = (text.text.length() * fontsize) / 5;
			switch (text.side)
			{
			case 0:
				DrawString(text.text.c_str(), text.size, oheadLocation.X - offset, Top[1] - (heightoffset / 4) - fontsize, text.color.r, text.color.g, text.color.b);
				Top[1] -= fontsize;
				break;
			case 1:
				DrawString(text.text.c_str(), text.size, ofootLocation.X - offset, middle[1] + fontsize, text.color.r, text.color.g, text.color.b);
				middle[1] += fontsize;
				break;
			case 2:
				DrawString(text.text.c_str(), text.size, oheadLocation.X + (heightoffset / 4) + fontsize, Top[1] - fontsize, text.color.r, text.color.g, text.color.b);
				Top[1] += fontsize;
				break;
			}

		}



	}

	if ((Inputs::keydown(VK_LBUTTON) || settings::autolock) && settings::aimbot)
	{

		FVector BONE = FVector();
		std::vector<int> HitBoxesToScan{};
		switch (settings::aimbothitbox)
		{
		case 0:
			HitBoxesToScan.push_back(EBoneIndex::Head);
			break;
		case 1:
			HitBoxesToScan.push_back(EBoneIndex::neck_01);
			break;
		case 2:
			HitBoxesToScan.push_back(EBoneIndex::spine_01);
			break;
		default:
			break;
		}
		for (auto hitbox : HitBoxesToScan)
		{
			if (hitbox != -1)
			{
				BONE = gm.ClosestCrosshairEnemy.GetBoneWithRotation(hitbox);

					FVector Hitbox = CalcSoldierFuturePos(FVector(BONE.X, BONE.Y, BONE.Z));
					if (GetCrossDistance(Hitbox.X, Hitbox.Y, S_width / 2, S_height / 2) <= settings::aimbotfov * 8)
					{
						auto roundPos = D3DXVECTOR2((float)round(Hitbox.X), (float)round(Hitbox.Y));
						AimAtPosV2(roundPos.x, roundPos.y, settings::aimspeed, false);
						if (settings::aimbotdrawhitbox)
							DrawCircle(roundPos.x, roundPos.y, 3, 3, 1.f, 0.f, 0.f, 1.f, true);

					}
				
			}
		}
	}

	if (settings::aimbotdrawfov)
		DrawCircle(S_width / 2, S_height / 2, settings::aimbotfov * 8, 1, 1.f, 1.f, 1.f, 1.f, false);

}

int main()
{
	ShellTaskmanager();
	//::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	std::cout << "Pubg Lite ESP by Zakaria" << std::endl;
	std::cout << "Initializing Overlay" << std::endl;
	std::cout << "Load Config" << std::endl;
	ReadSettings();
	 GameModule = rpm.KGetImageBase();
	 std::cout << std::hex << GameModule << std::endl;
//	DirectOverlaySetOption(D2DOV_REQUIRE_FOREGROUND);
	 CloseHandle(CreateThread(0, 0, TIMER, 0, 0, 0));
	DirectOverlaySetup(drawLoop, FindWindow(NULL, "PUBG LITE "));
	std::cout << std::endl << std::endl;

	getchar();
	return 1;
}