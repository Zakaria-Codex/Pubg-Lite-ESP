#include "Render.h"

Renderer* Renderer::m_pInstance;
Renderer::Renderer()
{
}

Renderer::~Renderer()
{
}

void Renderer::DrawHorBar(int x, int y, int w, int h, float Health, float MaxHealth, D3DXCOLOR color1, D3DXCOLOR color2)
{
	if (Health <= 0)
		Health = 1;
	if (MaxHealth < Health)
		MaxHealth = 100;

	int size = (w * Health / (MaxHealth / 100)) / 100;
	DrawBox(x, y, w, h,  1.f, 0.f, 0.f, 0.f, 1.f,false);
	DrawBox(x + 1, y + 1, w - 2, h - 2, 1.f, pasteColorA(color2),true);

	if (size == w)
		DrawBox(x + 1, y + 1, size - 2, h - 2, 1.f, pasteColorA(color1),true);
	else
		DrawBox(x + 1, y + 1, size, h - 2, 1.f, pasteColorA(color1), true);
}

void Renderer::DrawVerBar(int x, int y, int w, int h, float Health, float MaxHealth, D3DXCOLOR color1, D3DXCOLOR color2)
{
	if (Health <= 0)
		Health = 1;

	if (MaxHealth < Health)
		MaxHealth = 100;
	int size = (h * Health / (MaxHealth / 100)) / 100;

	DrawBox(x, y, w, h, 1.f,0.f, 0.f, 0.f, 1.f, false);
	DrawBox(x + 1, y + 1, w - 2, h - 2, 1.f, pasteColorA(color2),true);

	if (size == h)
		DrawBox(x + 1, y + 1 + h - size, w - 2, size - 2, 1.f, pasteColorA(color1), true);
	else
		DrawBox(x + 1, y + 1 + h - size, w - 2, size, 1.f, pasteColorA(color1), true);
}
void Renderer::DrawOutlineBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness)
{
	DrawBox(x, y, w, h, thickness,0.f, 0.f, 0.f, 1.f, false);
	DrawBox(x + 1, y + 1, w - 2, h - 2, thickness, pasteColorA(color), false);
	DrawBox(x + 2, y + 2, w - 4, h - 4, thickness,0.f, 0.f, 0.f, 1.f,false);
}

void Renderer::DrawCoalBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness)
{
	int iw = w / 4;
	int ih = h / 4;
	// top
	DrawLine(x, y, x + iw, y, thickness, pasteColorA(color));					// left
	DrawLine(x + w - iw, y, x + w, y, thickness, pasteColorA(color));			// right
	DrawLine(x, y, x, y + ih, thickness, pasteColorA(color));					// top left
	DrawLine(x + w - 1, y, x + w - 1, y + ih, thickness, pasteColorA(color));	// top right
														// bottom
	DrawLine(x, y + h, x + iw, y + h, thickness, pasteColorA(color));			// left
	DrawLine(x + w - iw, y + h, x + w, y + h, thickness, pasteColorA(color));	// right
	DrawLine(x, y + h - ih, x, y + h, thickness, pasteColorA(color));			// bottom left
	DrawLine(x + w - 1, y + h - ih, x + w - 1, y + h, thickness, pasteColorA(color));	// bottom right
}

void Renderer::DrawOutlineCoalBox(int x, int y, int w, int h, D3DXCOLOR color, float thickness)
{
	int iw = w / 4;
	int ih = h / 4;

	DrawCoalBox(x, y, w, h, D3DXCOLOR(0.f, 0.f, 0.f, 1.f));

	// top left
	DrawLine(x + 1, y + 1, x + iw, y + 1, thickness, pasteColorA(color));
	DrawLine(x + iw, y, x + iw, y + 2, thickness,0.f, 0.f, 0.f, 1.f);
	DrawLine(x + 1, y + 1, x + 1, y + ih, 1.f, pasteColorA(color));
	DrawLine(x, y + ih, x + 2, y + ih, thickness,0.f, 0.f, 0.f, 1.f);

	// top right
	DrawLine(x + w - iw, y + 1, x + w - 1, y + 1, thickness, pasteColorA(color));
	DrawLine(x + w - iw - 1, y, x + w - iw, y + 2, thickness,0.f, 0.f, 0.f, 1.f);
	DrawLine(x + w - 2, y + 1, x + w - 2, y + ih, thickness, pasteColorA(color));
	DrawLine(x + w - 2, y + ih, x + w, y + ih, thickness, 0.f, 0.f, 0.f, 1.f);

	// bottom left
	DrawLine(x + 1, y + h - ih, x + 1, y + h, thickness, pasteColorA(color));
	DrawLine(x, y + h - ih - 1, x + 2, y + h - ih - 1, thickness, 0.f, 0.f, 0.f, 1.f);
	DrawLine(x + 1, y + h - 1, x + iw, y + h - 1, thickness, pasteColorA(color));
	DrawLine(x + iw, y + h - 1, x + iw, y + h + 1, thickness,0.f, 0.f, 0.f, 1.f);

	// bottom right
	DrawLine(x + w - iw, y + h - 1, x + w - 1, y + h - 1, thickness, pasteColorA(color));
	DrawLine(x + w - iw - 1, y + h - 1, x + w - iw, y + h + 1, thickness, 0.f, 0.f, 0.f, 1.f);
	DrawLine(x + w - 2, y + h - ih, x + w - 2, y + h, thickness, pasteColorA(color));
	DrawLine(x + w - 2, y + h - ih - 1, x + w, y + h - ih - 1, thickness,0.f, 0.f, 0.f, 1.f);

	this->DrawCoalBox(x + 2, y + 2, w - 4, h - 4, D3DXCOLOR(0.f, 0.f, 0.f, 1.f));
}

void Renderer::DrawWindow(int x, int y, int w, int h, D3DXCOLOR Border, D3DXCOLOR Background)
{
	DrawBox(x, y, w, h, 1.f, pasteColorA(Border),false);
	DrawBox(x + 1, y + 1, w - 2, h - 2, 1.f,pasteColorA(Background),true);
}

void Renderer::DrawCrosshair(CrosshairStyle style, float x, float y, float size, float stroke, D3DXCOLOR color)
{
	if (style == CrosshairStyle::Dot)
	{
		DrawCircle(x, y, size,1.f, pasteColorA(color),true);
	}
	else if (style == CrosshairStyle::Plus)
	{
		DrawLine(x - size, y, x + size, y, stroke, pasteColorA(color));
		DrawLine(x, y - size, x, y + size, stroke, pasteColorA(color));
	}
	else if (style == CrosshairStyle::Cross)
	{
		DrawLine(x - size, y - size, x + size, y + size, stroke, pasteColorA(color));
		DrawLine(x + size, y - size, x - size, y + size, stroke, pasteColorA(color));
	}
	else if (style == CrosshairStyle::Gap)
	{
		DrawLine(x - size - stroke, y, x - stroke, y, stroke, pasteColorA(color));
		DrawLine(x + size + stroke, y, x + stroke, y, stroke, pasteColorA(color));
		DrawLine(x, y - size - stroke, x, y - stroke, stroke, pasteColorA(color));
		DrawLine(x, y + size + stroke, x, y + stroke, stroke, pasteColorA(color));
	}
	else if (style == CrosshairStyle::Diagonal)
	{
		DrawLine(x - size, y - size, x + size, y + size, stroke, pasteColorA(color));
		DrawLine(x + size, y - size, x - size, y + size, stroke, pasteColorA(color));
	}

}

Renderer* Renderer::GetInstance()
{
	if (!m_pInstance)
		m_pInstance = new Renderer();

	return m_pInstance;
}