#pragma once
#include "Settings.h"
#include "math.h"
#include "Offsets.h"
#include "Decrypt.h"
#include "kRpm.h"
#pragma warning(disable:4996)
static uint64_t GameModule = 0;
MoaRpm rpm("PUBG LITE ", MoaRpm::MOA_MODE::KERNEL);
static int S_width = 1920, S_height = 1080;
static uint64 Paddr[1500];
static int PlayerNum = 0;
double GetCrossDistance(double x1, double y1, double x2, double y2);
class Inputs {
private:
	static DWORD SendScanCode(WORD scan, BOOL up)
	{
		INPUT inp = { 0 };
		inp.type = INPUT_KEYBOARD;
		inp.ki.wScan = scan;
		inp.ki.dwFlags = KEYEVENTF_SCANCODE | (up ? KEYEVENTF_KEYUP : 0);
		return SendInput(1, &inp, sizeof(inp)) ? NO_ERROR : GetLastError();
	}
public:
	static bool mouse_move(int x, int y)
	{
		INPUT input;
		input.type = INPUT_MOUSE;
		input.mi.mouseData = 0;
		input.mi.time = 0;
		input.mi.dx = x;
		input.mi.dy = y;
		input.mi.dwFlags = MOUSEEVENTF_MOVE;
		SendInput(1, &input, sizeof(input));
		return true;
	}
	static DWORD SendVirtualKey(UINT vk, BOOL up)
	{
		UINT scan = MapVirtualKey(vk, MAPVK_VK_TO_VSC);
		return scan ? SendScanCode(scan, up) : ERROR_NO_UNICODE_TRANSLATION;
	}
	bool static keydown(int key)
	{
		return (GetAsyncKeyState(key) & 0x8000) != 0;
	}
};
namespace Decrypt
{
	template<class T> T __ROL__(T value, int count)
	{
		const unsigned int nbits = sizeof(T) * 8;

		if (count > 0)
		{
			count %= nbits;
			T high = value >> (nbits - count);
			if (T(-1) < 0)
				high &= ~((T(-1) << count));
			value <<= count;
			value |= high;
		}
		else
		{
			count = -count % nbits;
			T low = value << (nbits - count);
			value >>= count;
			value |= low;
		}
		return value;
	}
	ulong v11 = 0;
	inline byte __ROL1__(byte value, int count) { return __ROL__(value, count); }
	inline ushort __ROL2__(ushort value, int count) { return __ROL__(value, count); }
	inline uint __ROL4__(uint value, int count) { return __ROL__(value, count); }
	inline ulong __ROL8__(ulong value, int count) { return __ROL__(value, count); }
	inline byte __ROR1__(byte value, int count) { return __ROL__(value, -count); }
	inline ushort __ROR2__(ushort value, int count) { return __ROL__(value, -count); }
	inline uint __ROR4__(uint value, int count) { return __ROL__(value, -count); }
	inline ulong __ROR8__(ulong value, int count) { return __ROL__(value, -count); }

	// Generate a reference to pair of operands
	template<class T>  int16 __PAIR__(int8  high, T low) { return (((int16)high) << sizeof(high) * 8) | uint8(low); }
	template<class T>  int32 __PAIR__(int16 high, T low) { return (((int32)high) << sizeof(high) * 8) | uint16(low); }
	template<class T>  int64 __PAIR__(int32 high, T low) { return (((int64)high) << sizeof(high) * 8) | uint32(low); }
	template<class T> uint16 __PAIR__(uint8  high, T low) { return (((uint16)high) << sizeof(high) * 8) | uint8(low); }
	template<class T> uint32 __PAIR__(uint16 high, T low) { return (((uint32)high) << sizeof(high) * 8) | uint16(low); }
	template<class T> uint64 __PAIR__(uint32 high, T low) { return (((uint64)high) << sizeof(high) * 8) | uint32(low); }

	uint64 GameInstanceDec(uint64 inst)//++++++++++++++
	{
		__int64 v4;
		int v5;
		unsigned int v6;
		unsigned __int64 v7;
		v4 = rpm.read<uint64>(dwUWorld + inst);
		LODWORD(v7) = (~(_DWORD)v4 + 1425890107) ^ 0x7212461C;
		HIDWORD(v7) = (~(~HIDWORD(v4) + 446092664) + 1651193675) ^ 0xF3FDF33D;
		return v7;
	}
	uint64 DecryptActors(uint64 v5)
	{
		int v6;
		int v7;
		unsigned __int16 v8;
		int v9;
		unsigned __int16 v10;
		int v11;
		unsigned __int16 v12;
		__int64 v31;


		if (!v5) return 0;

		v6 = ((v5 & 0xFFFF0000 | (unsigned __int16)v5 ^ ((unsigned int)v5 >> 16)) - 1629592062) >> 16;
		v7 = v6 ^ (unsigned __int16)((v5 ^ WORD1(v5)) + 26114);
		v8 = __ROR2__(v6, 8);
		v9 = v8;
		v10 = __ROR2__(WORD3(v5), 8);
		LOWORD(v6) = __ROR2__((v5 >> 32) ^ WORD3(v5), 8);
		LODWORD(v31) = (v7 | (v9 << 16)) ^ 0x9EDE6602;
		v11 = ((v10 << 16) | (unsigned __int16)v6) - 1648255678;
		v12 = __ROR2__(v11 ^ HIWORD(v11), 8);
		HIDWORD(v31) = (v11 & 0xFFFF0000 | v12) ^ 0x623E62BE;

		return v31;
	}

	uint64 ULevelDec(uint64 inst)//
	{
		unsigned __int64 v18;
		__int64 v261;
		v18 = rpm.read<uint64>(dwUWorld + inst);
		LODWORD(v261) = (v18 - 1042594514) ^ 0xF0F03010;
		HIDWORD(v261) = (HIDWORD(v18) - 1589798400) ^ 0x10F010F0;
		return v261;
	}
	/*uint64 ULevelDec(uint64 inst)//
	{
		unsigned __int64 v18;
		__int64 v261;
		v18 = inst;
		LODWORD(v261) = (v18 - 1042594514) ^ 0xF0F03010;
		HIDWORD(v261) = (HIDWORD(v18) - 1589798400) ^ 0x10F010F0;
		return v261;
	}*/
	uint64 LocalDec(uint64 inst, uint64 inst2)//+++++++++++++++
	{
		int v2;
		int v3;
		__int64 v5;
		__int64 v6;
		__int64 v1;
		v6 = rpm.read<uint64>(inst + inst2);
		v1 = rpm.read<uint64>(v6);
		v2 = __ROL4__(v1 ^ 0xE9EA03BD, 8);
		LODWORD(v1) = __ROR4__(HIDWORD(v1) ^ 0x4E19C6E8, 16);
		v3 = __ROL4__((v2 - 2080050116) ^ 0x84EA03BD, 8);
		LODWORD(v1) = __ROR4__((v1 - 2084863044) ^ 0xE919C6E8, 16);
		LODWORD(v5) = v3 ^ 0x8404F43C;
		HIDWORD(v5) = v1 ^ 0x7C447C44;
		return v5;
	}
	INT32 ObjID(INT32 ID)//
	{
		int v33;
		v33 = __ROL4__(ID ^ 0xF7B20EA6, 14) ^ (__ROL4__(ID ^ 0xF7B20EA6, 14) << 16) ^ 0xF914F7B2;
		return v33;
	}

	uint64 PlayerControllerDec(uint64 inst, uint64 inst2)//++++++++++++++++
	{
		__int64 v15;
		unsigned __int64 v16;
		unsigned __int16 v17;
		unsigned int v18;
		unsigned __int16 v19;
		unsigned __int16 v20;
		unsigned int v21;
		unsigned __int16 v22;
		__int64 v96;
		v15 = rpm.read<uint64>(inst + inst2);
		v16 = v15 >> 32;
		v17 = __ROR2__(WORD1(v15), 8);
		v18 = ((unsigned __int16)v15 ^ ((unsigned int)v15 >> 16) | (v17 << 16)) - 1195845432;
		v19 = __ROR2__(HIWORD(v18), 8);
		LODWORD(v96) = ((unsigned __int16)v18 ^ (v18 >> 16) | (v19 << 16)) ^ 0xB8B8D8C8;
		v20 = __ROL2__((v15 >> 32) ^ WORD1(v16), 8);
		v21 = (HIDWORD(v15) & 0xFFFF0000 | v20) - 1211648056;
		v22 = __ROL2__((v20 - 18488) ^ HIWORD(v21), 8);
		HIDWORD(v96) = (v21 & 0xFFFF0000 | v22) ^ 0x48384838;
		return v96;
	}

#define GNames 0x4680CB0
#define _DEBUG_
	static bool bPrintOnce = false;

	uint64 InPawnDec(uint64 cryptedOffset)//+
	{
		unsigned __int64 v1;
		int v2;
		int v3;
		__int64 v5;
		v1 = rpm.read<uint64>(cryptedOffset);
		v2 = __ROL4__(v1, 16);
		LODWORD(v1) = __ROR4__(HIDWORD(v1), 8);
		v3 = __ROL4__(v2 - 1675842396, 16);
		LODWORD(v1) = __ROR4__(v1 - 1692165340, 8);
		LODWORD(v5) = v3 ^ 0x9C1CACA4;
		HIDWORD(v5) = v1 ^ 0x64DC64DC;
		return v5;
	}
	template <typename PtrType>
	PtrType Decrypt(ULONG_PTR v1) //GetCurrentLevel, RootComponent, mesh
	{
		int v2;
		int v3;
		__int64 v5;

		if (!v1) return 0;

		v2 = __ROL4__(v1, 16);
		LODWORD(v1) = __ROR4__(HIDWORD(v1), 8);
		v3 = __ROL4__(v2 - 1675842396, 16);
		LODWORD(v1) = __ROR4__(v1 - 1692165340, 8);
		LODWORD(v5) = v3 ^ 0x9C1CACA4;
		HIDWORD(v5) = v1 ^ 0x64DC64DC;

		return (PtrType)v5;
	}
	struct ObjectName
	{
		char data[64];
	};
	uint64 gnames(uint64 GName)
	{
		DWORD64 v42 = 0;
		DWORD64 v4 = rpm.read<DWORD64>(GameModule + GName);
		LODWORD(v42) = __ROL4__(__ROL4__(v4, 16) + 1827421396, 16) ^ 0x6CEC3CD4;
		HIDWORD(v42) = __ROR4__(__ROR4__(HIDWORD(v4), 8) + 1800629076, 8) ^ 0x94AC94AC;

		DWORD64 v43 = 0;
		DWORD64 v22 = rpm.read<DWORD64>(v42);
		LODWORD(v43) = __ROL4__(__ROL4__(v22 + 2129265597, 16) - 207398508, 16) ^ 0xD9B955D7;
		HIDWORD(v43) = __ROR4__(__ROR4__(HIDWORD(v22) - 484849944, 8) - 695197921, 8) ^ 0xA789A7C9;

		DWORD64 v44 = 0;
		DWORD64 v24 = rpm.read<DWORD64>(v43);
		DWORD64 v25 = __PAIR__(((HIDWORD(v24) ^ 0xC3E63917) + 240258770) ^ 0x26B437C5, ((v24 ^ 0x2815FC42) + 223155602) ^ 0x7FA7162C);
		USHORT v27 = __ROL2__(((unsigned int)v25 ^ 0x9EDE6602) >> 16, 8);
		DWORD32 v28 = ((v27 << 16) | (unsigned __int16)v25 ^ 0x6602 ^ v27) + 1629592062;
		DWORD32 v29 = (unsigned __int16)((v25 ^ 0x6602 ^ v27) - 26114) ^ (v28 >> 16);
		DWORD32 v30 = (HIDWORD(v25) ^ 0x623E62BEu) >> 16;
		LODWORD(v44) = v28 & 0xFFFF0000 | v29;
		USHORT v31 = __ROL2__(WORD2(v25) ^ 0x62BE, 8);
		DWORD32 v32 = ((v30 << 16) | v30 ^ v31) + 1648255678;
		LOWORD(v32) = __ROL2__((v30 ^ v31) + 25278, 8);
		LOWORD(v30) = __ROL2__(HIWORD(v32), 8);
		HIDWORD(v44) = ((unsigned __int16)v30 << 16) | (unsigned __int16)v30 ^ (unsigned __int16)v32;

		DWORD64 v36 = 0;
		DWORD64 v9 = v44 >> 32;
		DWORD32 v10 = (v44 & 0xFFFF0000 | (unsigned __int16)v44 ^ ((unsigned int)v44 >> 16)) - 1629592062;
		LODWORD(v36) = ((unsigned __int16)v10 ^ (v10 >> 16) | ((unsigned __int16)__ROR2__(HIWORD(v10), 8) << 16)) ^ 0x9EDE6602;
		DWORD32 v11 = ((unsigned __int16)__ROR2__(WORD2(v44) ^ WORD1(v9), 8) | ((unsigned __int16)__ROR2__(WORD1(v9), 8) << 16)) - 1648255678;
		HIDWORD(v36) = (v11 & 0xFFFF0000 | (unsigned __int16)__ROR2__(v11 ^ HIWORD(v11), 8)) ^ 0x623E62BE;

		DWORD64 v37 = 0;
		DWORD64 v14 = rpm.read<DWORD64>(v36 + 8);
		LODWORD(v37) = __ROR4__(__ROR4__(v14, 8) + 1467423737, 8) ^ 0x57771BF9;
		HIDWORD(v37) = (HIDWORD(v14) - 698820967) ^ 0x29A72967;

		return v37;
	}
	std::string GetGNamesByObjID(int32_t ObjectID)
	{
		uint64 GName = gnames(GNames);
		int64_t fNamePtr = rpm.read<uint64_t>(GName + int(ObjectID / 0x408C) * 0x8);
		int64_t fName = rpm.read<uint64_t>(fNamePtr + int(ObjectID % 0x408C) * 0x8);
		ObjectName pBuffer = rpm.read<ObjectName>(fName + 0x10);
		return std::string(pBuffer.data);
	}

}
struct sPlayerName
{
	char data[64];
};
class Player {
private:

	FTransform GetBoneIndex(uint64 dwbonemesh, int indexnum)
	{
		uint64 bonearray = rpm.read<uint64>(dwbonemesh + offset_boneArray);
		return rpm.read<FTransform>(bonearray + (indexnum * 0x30));
	}

public:
	Player() {}
	Player(uint64 _ptr) {
		this->ptr = _ptr;

		this->Head = GetBoneWithRotation(6);
		this->Location = GetBoneWithRotation(62);
		this->Team = rpm.read<int>(this->ptr + TeamID);
		this->Health = rpm.read<float>(this->ptr + bHealth);
		this->IsAbot = rpm.read<bool>(this->ptr + 0x800);
		this->inVeh = rpm.read<uint64>(this->ptr + CurrentVehicle);
	}
	uint64 ptr = 0;
	float Health = 0;
	INT Team = 0;
	BOOL IsAbot = false;
	uint64 inVeh = 0;
	FVector Head = FVector();
	FVector Location = FVector();
	FLOAT Distance = 0;
	FVector GetBoneWithRotation( int boneindexnum)
	{
		uint64 CurrentActorMesh = Decrypt::Decrypt<uint64>(rpm.read<uint64>(this->ptr + Mesh));
		FTransform bone = GetBoneIndex(CurrentActorMesh, boneindexnum);
		FTransform ComponentToWorld = rpm.read<FTransform>(CurrentActorMesh + offset_ComponentToWorld);
		D3DMATRIX Matrix;
		Matrix = MatrixMultiplication(bone.ToMatrixWithScale(), ComponentToWorld.ToMatrixWithScale());

		return FVector(Matrix._41, Matrix._42, Matrix._43);
	}
	std::string Name()
	{
		uint64 fName = rpm.read<uint64>(this->ptr + PlayerName);
		sPlayerName pBuffer = rpm.read<sPlayerName>(fName);
		sPlayerName pBuffer2 = rpm.read<sPlayerName>(fName + 0x2);
		sPlayerName pBuffer3 = rpm.read<sPlayerName>(fName + 0x4);
		sPlayerName pBuffer4 = rpm.read<sPlayerName>(fName + 0x6);
		sPlayerName pBuffer5 = rpm.read<sPlayerName>(fName + 0x8);
		return std::string(pBuffer.data) + std::string(pBuffer2.data) + std::string(pBuffer3.data) + std::string(pBuffer4.data) + std::string(pBuffer5.data);
	}
	BOOL IsValid() {
		if ((this->Location.X != NULL) &&
			(this->Health > NULL) &&
			(this->ptr != NULL)) return true;
		return false;
	}
};
class Manager {
private:
	uint64	PlayerController = Decrypt::PlayerControllerDec(Decrypt::LocalDec(Decrypt::GameInstanceDec(GInstance), UlocalPlayer), 0x30);
	uint64	PlayerCamera = rpm.read<uint64>(PlayerController + PlayerCameraManager);
	FMinimalViewInfo CameraCacheEntry = rpm.read<FMinimalViewInfo>(PlayerCamera + CameraCache + POV);

public:
	Player LocalPlayer = NULL;
	std::vector<Player> Players = std::vector<Player>();
	Player ClosestVisibleEnemy = NULL;
	Player ClosestCrosshairEnemy = NULL;

	Manager(int width, int height) {
		S_width = width;
		S_height = height;

		uint64 LocalPawn = rpm.read<uint64>(PlayerController + STExtraBaseCharacter);
		this->LocalPlayer = Player(LocalPawn);
		uint64 LocalActorMesh = Decrypt::Decrypt<uint64>(rpm.read<uint64>(this->LocalPlayer.ptr + Mesh));

		for (int i = 0; i < PlayerNum; i++) {
			Player player(Paddr[i]);
			uint64 CurrentActorMesh = Decrypt::Decrypt<uint64>(rpm.read<uint64>(player.ptr + Mesh));

			if (player.ptr != 0);// break;
			if (player.IsValid() && player.ptr != this->LocalPlayer.ptr)
			{
				player.Distance = LocalPlayer.Location.Distance(player.Head) / 100.f;
				this->Players.push_back(player);

			}
		}
		float closestcrosshair = FLT_MAX;
		for (size_t i = 0; i < this->Players.size(); i++)
		{

			FVector out = WorldToScreen(this->Players[i].Location);

				float crossdis = GetCrossDistance(out.X, out.Y, S_width / 2, S_height / 2);
			if ((crossdis < closestcrosshair)) {
				if (this->Players[i].Team != this->LocalPlayer.Team && this->Players[i].Distance < 125) {
					ClosestCrosshairEnemy = this->Players[i];
					closestcrosshair = crossdis;
				}
			}

		}
		float closestdis = FLT_MAX;
		for (int i = 0; i < this->Players.size(); i++) {
			if ((this->Players[i].Distance < closestdis)) {
				if (this->Players[i].Team != this->LocalPlayer.Team) {
					ClosestVisibleEnemy = this->Players[i];
					closestdis = this->Players[i].Distance;
				}
			}
		}


	}
	FVector WorldToScreen( FVector WorldLocation)
	{
		FVector Screenlocation = FVector(0, 0, 0);
		FRotator Rotation = CameraCacheEntry.Rotation;
		D3DMATRIX tempMatrix = Matrix(Rotation);

		FVector vAxisX, vAxisY, vAxisZ;

		vAxisX = FVector(tempMatrix.m[0][0], tempMatrix.m[0][1], tempMatrix.m[0][2]);
		vAxisY = FVector(tempMatrix.m[1][0], tempMatrix.m[1][1], tempMatrix.m[1][2]);
		vAxisZ = FVector(tempMatrix.m[2][0], tempMatrix.m[2][1], tempMatrix.m[2][2]);

		FVector vDelta = WorldLocation - CameraCacheEntry.Location;
		FVector vTransformed = FVector(vDelta.Dot(vDelta, vAxisY), vDelta.Dot(vDelta, vAxisZ), vDelta.Dot(vDelta, vAxisX));

		if (vTransformed.Z < 1.f)
			vTransformed.Z = 1.f;

		float FovAngle = CameraCacheEntry.FOV;

		float ScreenCenterX = S_width / 2;
		float ScreenCenterY = S_height / 2;

		Screenlocation.X = ScreenCenterX + vTransformed.X * (ScreenCenterX / tanf(FovAngle * (float)M_PI / 360.f)) / vTransformed.Z;
		Screenlocation.Y = ScreenCenterY - vTransformed.Y * (ScreenCenterX / tanf(FovAngle * (float)M_PI / 360.f)) / vTransformed.Z;

		return Screenlocation;
	}

};

double GetCrossDistance(double x1, double y1, double x2, double y2)
{
	return sqrt(pow((x2 - x1), 2) + pow((y2 - y1), 2));
}
void AimAtPosV2(float x, float y, float speed, bool smooth)
{
	int ScreenCenterX = S_width / 2, ScreenCenterY = S_height / 2;

	float AimSpeed = (float)speed;
	float TargetX = 0;
	float TargetY = 0;

	//X Axis
	if (x != 0)
	{
		if (x > ScreenCenterX)
		{
			TargetX = -(ScreenCenterX - x);
			TargetX /= AimSpeed;
			TargetX += settings::aimlock;
			if (TargetX + ScreenCenterX > ScreenCenterX * 2) TargetX = 0;
		}

		if (x < ScreenCenterX)
		{
			TargetX = x - ScreenCenterX;
			TargetX /= AimSpeed;
			TargetX -= settings::aimlock;
			if (TargetX + ScreenCenterX < 0) TargetX = 0;
		}
	}

	//Y Axis

	if (y != 0)
	{
		if (y > ScreenCenterY)
		{
			TargetY = -(ScreenCenterY - y);
			TargetY /= AimSpeed;
			TargetY += settings::aimlock;
			if (TargetY + ScreenCenterY > ScreenCenterY * 2) TargetY = 0;
		}

		if (y < ScreenCenterY)
		{
			TargetY = y - ScreenCenterY;
			TargetY /= AimSpeed;
			TargetY -= settings::aimlock;
			if (TargetY + ScreenCenterY < 0) TargetY = 0;
		}
	}

	if (!smooth)
	{
		Inputs::mouse_move((int)TargetX, (int)(TargetY));
		return;
	}

	TargetX /= 10;
	TargetY /= 10;

	if (abs(TargetX) < 1)
	{
		if (TargetX > 0)
		{
			TargetX = 1;
		}
		if (TargetX < 0)
		{
			TargetX = -1;
		}
	}
	if (abs(TargetY) < 1)
	{
		if (TargetY > 0)
		{
			TargetY = 1;
		}
		if (TargetY < 0)
		{
			TargetY = -1;
		}
	}
	Inputs::mouse_move((int)TargetX, (int)(TargetY));

}
FVector CalcSoldierFuturePos(FVector InVec)
{
	Manager gm(S_width, S_height);
	FVector NewPos, OutPos;
	NewPos = gm.WorldToScreen(InVec);
		OutPos.X = NewPos.X;
		OutPos.Y = NewPos.Y;
		OutPos.Z = NewPos.Z;	
	return OutPos;
}
