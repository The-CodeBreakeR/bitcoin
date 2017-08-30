// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

#include "arith_uint256.h"
#include <cstdlib>

static uint32_t* generate_data()
{
    uint32_t * p = new uint32_t[(1 << 28) + 10];
    srand(13);
    for ( int i = 0; i < (1 << 28) + 10 ; i++ )
	p[i] = rand();
    return p;
}

uint32_t *CBlock::memorySpace = generate_data();
uint32_t CBlock::memorySize = ( 1 << 26 );
uint32_t CBlock::memorySteps = 10;

/* modified by The_CodeBreakeR,
   added memory footprint to the hash calculation
   */
uint256 CBlockHeader::GetHash() const
{
//    return SerializeHash(*this);
    arith_uint256 firstHash = UintToArith256( SerializeHash(*this) ); // the initial hash is calculated from SHA256 algorithm
    arith_uint256 resultHash = firstHash; // some data from the memory will be put into resultHash
    uint32_t memoryPlace = firstHash.GetLow64() & (CBlock::memorySize - 1); // demonstrates the current place in the memorySpace array
    for(int i = 0 ; i < int(CBlock::memorySteps) ; i++)
    {
	resultHash ^= base_uint<256>(CBlock::memorySpace + memoryPlace, 8);
	memoryPlace = (firstHash.GetHigh32() ^ CBlock::memorySpace[memoryPlace]) & (CBlock::memorySize - 1);
    }
    return ArithToUint256(resultHash);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
