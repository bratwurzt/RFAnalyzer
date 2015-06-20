package com.mantz_it.rfanalyzer.psk.taximdt;

public class Unknown007e
{
  public String line[] = new String[20];

  //main decode method
  public void decode(ExBitSet rawData)
  {
    // Create a new display stamp object //
    DisplayStamp timeStamp = new DisplayStamp();
    line[0] = timeStamp.getTimestamp();
    line[0] = line[0] + " Unknown Protocol (0x007e) ";
    line[1] = rawData.convertToString(0, rawData.length());
  }
}
