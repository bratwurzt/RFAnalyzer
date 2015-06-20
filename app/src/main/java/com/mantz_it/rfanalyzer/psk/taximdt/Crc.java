package com.mantz_it.rfanalyzer.psk.taximdt;

public class Crc
{
  private int crc16Value;

  //getters and setters
  public int getCrc16Value()
  {
    return crc16Value;
  }

  public void setCrc16Value(int crc16Value)
  {
    this.crc16Value = crc16Value;
  }

  // The CCITT CRC16 routine //
  public void ccitt_crc16(int in)
  {
    boolean c15, bit;
    byte c = (byte)in;
    for (int i = 0; i < 8; i++)
    {
      c15 = ((crc16Value >> 15 & 1) == 1);
      bit = ((c >> (7 - i) & 1) == 1);
      crc16Value <<= 1;
      if (c15 ^ bit)
      {
        crc16Value ^= 0x1021;
      }
    }
    crc16Value = crc16Value & 0xffff;
  }

  // The MPT1317 CRC16 routine //
  public void mpt_crc16(boolean bit)
  {
    crc16Value <<= 1;
    boolean c15 = ((crc16Value >> 15 & 1) == 1);
    if (c15 ^ bit)
    {
      crc16Value ^= 0x6815;
    }
    crc16Value = crc16Value & 0x7fff;
  }
}
