#pragma once
#include "ProcessMemory.h" 

namespace offsets {
	//client.dll
	constexpr std::ptrdiff_t m_iTeamNum = 0x3EB;
	constexpr std::ptrdiff_t m_iHealth = 0x34C;
	constexpr std::ptrdiff_t m_iIDEntIndex = 0x3ECC;
	constexpr std::ptrdiff_t m_hPawn = 0x6B4;

	//offsets

	//std::string dwEntityListPattern = "48 8b 0d ? ? ? ? 48 89 7c 24 ? 8b fa c1 eb";
	//std::string dwPlayerControllerPattern = "48 8B 05 ? ? ? ? 48 85 C0 74 4F";
	//std::string dwPlayerPawnPattern = "48 8D 05 ? ? ? ? C3 CC CC CC CC CC CC CC CC 48 83 EC ? 8B 0D";
		
	
}

