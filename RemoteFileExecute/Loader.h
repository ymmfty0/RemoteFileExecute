#pragma once

#include <Windows.h>
#include <stdio.h>


class Loader
{
private:
public:
	Loader();
	~Loader();
	void Execute(LPBYTE buff);
	BOOL Validating(LPBYTE buff);

};

