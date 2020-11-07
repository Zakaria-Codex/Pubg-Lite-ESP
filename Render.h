#pragma once
#include "Includes.h"
#include "DirectOverlay.h"

class Renderer
{
public:
	static Renderer* GetInstance();
private:
	Renderer();
	~Renderer();
public:
	enum CrosshairStyle
	{
		Dot,
		Plus,
		Cross,
		Gap,
		Diagonal,
	};

	void DrawHorBar(int x, int y, int w, int h, float Health, float MaxHealth, D3DXCOLOR color1, D3DXCOLOR color2);
	void DrawVerBar(int x, int y, int w, int h, float Health, float MaxHealth, D3DXCOLOR color1, D3DXCOLOR color2);
	void DrawOutlineBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness = 1.0f);
	void DrawCoalBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness = 1.0f);
	void DrawOutlineCoalBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness = 1.0f);
	void DrawWindow(int x, int y, int w, int h, D3DXCOLOR Border, D3DXCOLOR Background);

	void DrawCrosshair(CrosshairStyle style, float x, float y, float size, float stroke, D3DXCOLOR color);
private:
	static Renderer* m_pInstance;
};