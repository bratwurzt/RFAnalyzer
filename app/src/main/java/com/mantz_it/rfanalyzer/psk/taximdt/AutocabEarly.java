package com.mantz_it.rfanalyzer.psk.taximdt;

// This class handles what is believed to be early Autocab traffic
public class AutocabEarly
{
  public String line[] = new String[50];
  public boolean view_binary, view_special_ascii, view_bad_crc,
      view_crc_warnings;
  public int system_code, block_count;

  // Decode the Autocab (early) traffic
  public void decode(ExBitSet raw_data, SystemInfo si)
  {
    // Create a boolean array to contain the results
    // of all the block CRC results
    boolean block_crc_result[] = new boolean[block_count];
    int calling = 0;
    int called = 0;
    int ascii;
    int count;
    int crc_failure_count = 0;
    int packetType = 0;
    int garbageByteCount = 0;
    int bend;
    int bytes;

    // Create a new display stamp object //
    DisplayStamp time_stamp = new DisplayStamp();
    line[0] = time_stamp.getTimestamp();

    // Create a channel statistics object //
    ChannelStatistics channelStats = new ChannelStatistics();

    // CRC check all blocks //
    for (int i = 0; i < block_count; i++)
    {
      block_crc_result[i] = block_crc(raw_data, (i * 64));
      // Look out for failures //
      if (block_crc_result[i] == false)
      {
        crc_failure_count++;
      }
    }

    // If the CRC is good increment the good autocab packet counter else
    // increment the bad packets counter//
    if (crc_failure_count > 0)
    {
      channelStats.incGoodAutocabPacketsCounter();
    }
    else
    {
      channelStats.incBadAutocabPacketsCounter();
    }

    // If any have failed this is bad data //
    if ((crc_failure_count > 0) && (view_bad_crc == false))
    {
      // Does the user want to see bad CRC warnings //
      if (view_crc_warnings == true)
      {
        line[0] = line[0] + " Bad Autocab CRC !";
      }
      else
      {
        line[0] = "";
      }
      return;
    }

    //get the packet type
    packetType = getPacketType(raw_data);

    //the number of garbage bytes in the last packet
    garbageByteCount = getGarbageBytes(raw_data);

    //get the calling ID
    calling = getCallingIdent(raw_data);

    //get the called ID
    called = getCalledIdent(raw_data);

    // Make up the display //
    // If the user wants to see bad data then at least mark it //
    if ((crc_failure_count > 0) && (view_bad_crc == true))
    {
      line[0] = line[0] + " (BAD CRC ! ";
      for (int i = 0; i < block_count; i++)
      {
        if (block_crc_result[i] == true)
        {
          line[0] = line[0] + "O";
        }
        else
        {
          line[0] = line[0] + "X";
        }
      }
      line[0] = line[0] + ")";
    }

    // Handle the rest of the display //
    line[0] = line[0] + " Autocab (0xb433) : ";
    line[0] = line[0] + "Calling ";

    // Check if this user has been identified
    // Note that currently this feature will only work when monitoring the
    // base
    // side of a radio link
    String sys_name = si.nameSearch(calling);
    if (sys_name == null)
    {
      line[0] = line[0] + Integer.toHexString(calling);
    }
    else
    {
      line[0] = line[0] + sys_name;
      line[0] = line[0] + " (";
      line[0] = line[0] + Integer.toHexString(calling);
      line[0] = line[0] + ")";
    }
    line[0] = line[0] + " : Called ";
    line[0] = line[0] + Integer.toHexString(called);
    line[0] = line[0] + " : Type ";
    line[0] = line[0] + Integer.toString(packetType);
    line[0] = line[0] + " (";
    line[0] = line[0] + Integer.toString(block_count);
    line[0] = line[0] + " Blocks)";

    // Display all the binary data if the user wants to //
    if (view_binary == true)
    {
      // Run through each block //
      for (int b = 0; b < block_count; b++)
      {
        // Now run through each of the 48 bits in that block //
        for (int i = (b * 64); i < (b + 1) * 64; i++)
        {
          if (raw_data.get(i) == true)
          {
            line[1] = line[1] + "1";
          }
          else
          {
            line[1] = line[1] + "0";
          }
        }
        // Add a space between each block //
        line[1] = line[1] + " ";
      }
    }

    // Display ASCII in the blocks //
    // But only if there are more than 2 blocks and this isn't a type 14
    // message //
    if ((block_count < 2) || (packetType != 14))
    {
      return;
    }
    ascii = 0;
    count = 1;

    // Run through each block //
    for (int b = 2; b < block_count; b++)
    {
      bend = ((b + 1) * 64) - 16;
      // If this is the last block deduct any garbage bytes //
      if (b == block_count - 1)
      {
        bend = bend - (garbageByteCount * 8);
      }
      // Now run through each of the 48 bits in that block //
      for (int i = (b * 64); i < bend; i++)
      {
        ascii <<= 1;
        if (raw_data.get(i) == true)
        {
          ascii++;
        }
        if (count == 8)
        {
          // Only view letters and numbers //
          if ((ascii > 31) && (ascii < 123))
          {
            line[2] = line[2] + Character.toString((char)ascii);
          }
          // ASCII 0 is used as a line feed by Autocab (early) //
          if (ascii == 0)
          {
            if (view_special_ascii == true)
            {
              line[2] = line[2] + "<NULL>";
            }
            else
            {
              line[2] = line[2] + " ";
            }
          }
          ascii = 0;
          count = 1;
        }
        else
        {
          count++;
        }
      }
    }

    // Calculate the number of bytes in this message //
    bytes = (block_count * 64) / 8;

    // Add this to the total number of bytes //
    channelStats.addBytesToTotal(bytes);
  }

  private int getPacketType(ExBitSet rawData)
  {
    int pType = 0;
    // Get the packet type //
    if (rawData.get(24) == true)
    {
      pType = 128;
    }
    if (rawData.get(25) == true)
    {
      pType = pType + 64;
    }
    if (rawData.get(26) == true)
    {
      pType = pType + 32;
    }
    if (rawData.get(27) == true)
    {
      pType = pType + 16;
    }
    if (rawData.get(28) == true)
    {
      pType = pType + 8;
    }
    if (rawData.get(29) == true)
    {
      pType = pType + 4;
    }
    if (rawData.get(30) == true)
    {
      pType = pType + 2;
    }
    if (rawData.get(31) == true)
    {
      pType++;
    }
    return pType;
  }

  private int getGarbageBytes(ExBitSet rawData)
  {
    int gBytes = 0;
    // The number of garbage bytes in the last packet //
    if (rawData.get(32) == true)
    {
      gBytes = 128;
    }
    if (rawData.get(33) == true)
    {
      gBytes = gBytes + 64;
    }
    if (rawData.get(34) == true)
    {
      gBytes = gBytes + 32;
    }
    if (rawData.get(35) == true)
    {
      gBytes = gBytes + 16;
    }
    if (rawData.get(36) == true)
    {
      gBytes = gBytes + 8;
    }
    if (rawData.get(37) == true)
    {
      gBytes = gBytes + 4;
    }
    if (rawData.get(38) == true)
    {
      gBytes = gBytes + 2;
    }
    if (rawData.get(39) == true)
    {
      gBytes++;
    }

    return gBytes;
  }

  private int getCallingIdent(ExBitSet rawData)
  {
    int callingId = 0;
    // Calculate the calling ident //
    if (rawData.get(64) == true)
    {
      callingId = 32768;
    }
    if (rawData.get(65) == true)
    {
      callingId = callingId + 16384;
    }
    if (rawData.get(66) == true)
    {
      callingId = callingId + 8192;
    }
    if (rawData.get(67) == true)
    {
      callingId = callingId + 4096;
    }
    if (rawData.get(68) == true)
    {
      callingId = callingId + 2048;
    }
    if (rawData.get(69) == true)
    {
      callingId = callingId + 1024;
    }
    if (rawData.get(70) == true)
    {
      callingId = callingId + 512;
    }
    if (rawData.get(71) == true)
    {
      callingId = callingId + 256;
    }
    if (rawData.get(72) == true)
    {
      callingId = callingId + 128;
    }
    if (rawData.get(73) == true)
    {
      callingId = callingId + 64;
    }
    if (rawData.get(74) == true)
    {
      callingId = callingId + 32;
    }
    if (rawData.get(75) == true)
    {
      callingId = callingId + 16;
    }
    if (rawData.get(76) == true)
    {
      callingId = callingId + 8;
    }
    if (rawData.get(77) == true)
    {
      callingId = callingId + 4;
    }
    if (rawData.get(78) == true)
    {
      callingId = callingId + 2;
    }
    if (rawData.get(79) == true)
    {
      callingId++;
    }

    return callingId;
  }

  private int getCalledIdent(ExBitSet rawData)
  {
    int calledId = 0;
    // Calculate the called ident //
    if (rawData.get(80) == true)
    {
      calledId = 32768;
    }
    if (rawData.get(81) == true)
    {
      calledId = calledId + 16384;
    }
    if (rawData.get(82) == true)
    {
      calledId = calledId + 8192;
    }
    if (rawData.get(83) == true)
    {
      calledId = calledId + 4096;
    }
    if (rawData.get(84) == true)
    {
      calledId = calledId + 2048;
    }
    if (rawData.get(85) == true)
    {
      calledId = calledId + 1024;
    }
    if (rawData.get(86) == true)
    {
      calledId = calledId + 512;
    }
    if (rawData.get(87) == true)
    {
      calledId = calledId + 256;
    }
    if (rawData.get(88) == true)
    {
      calledId = calledId + 128;
    }
    if (rawData.get(89) == true)
    {
      calledId = calledId + 64;
    }
    if (rawData.get(90) == true)
    {
      calledId = calledId + 32;
    }
    if (rawData.get(91) == true)
    {
      calledId = calledId + 16;
    }
    if (rawData.get(92) == true)
    {
      calledId = calledId + 8;
    }
    if (rawData.get(93) == true)
    {
      calledId = calledId + 4;
    }
    if (rawData.get(94) == true)
    {
      calledId = calledId + 2;
    }
    if (rawData.get(95) == true)
    {
      calledId++;
    }
    return calledId;
  }

  // CRC check an early Autocab block //
  // Returns true is all OK and false if not //
  // block_start is 0 if first block and 64 if the second //
  public boolean block_crc(ExBitSet bits, int block_start)
  {
    int i, act = 0;
    // Calculate the actual CRC of the block //
    if (bits.get(block_start + 48) == true)
    {
      act = 16384;
    }
    if (bits.get(block_start + 49) == true)
    {
      act = act + 8192;
    }
    if (bits.get(block_start + 50) == true)
    {
      act = act + 4096;
    }
    if (bits.get(block_start + 51) == true)
    {
      act = act + 2048;
    }
    if (bits.get(block_start + 52) == true)
    {
      act = act + 1024;
    }
    if (bits.get(block_start + 53) == true)
    {
      act = act + 512;
    }
    if (bits.get(block_start + 54) == true)
    {
      act = act + 256;
    }
    if (bits.get(block_start + 55) == true)
    {
      act = act + 128;
    }
    if (bits.get(block_start + 56) == true)
    {
      act = act + 64;
    }
    if (bits.get(block_start + 57) == true)
    {
      act = act + 32;
    }
    if (bits.get(block_start + 58) == true)
    {
      act = act + 16;
    }
    if (bits.get(block_start + 59) == true)
    {
      act = act + 8;
    }
    if (bits.get(block_start + 60) == true)
    {
      act = act + 4;
    }
    if (bits.get(block_start + 61) == true)
    {
      act = act + 2;
    }
    if (bits.get(block_start + 62) == true)
    {
      act++;
    }

    // Calculate the CRC //
    // Create a CRC object //
    Crc autocabEarlyCrc = new Crc();

    // Clear the CRC counter //
    autocabEarlyCrc.setCrc16Value(0);

    for (i = 0; i < 48; i++)
    {
      autocabEarlyCrc.mpt_crc16(bits.get(block_start + i));
    }

    // Invert the last bit //
    autocabEarlyCrc.setCrc16Value(autocabEarlyCrc.getCrc16Value() ^ 0x01);

    // Compare both CRC values //
    if (act == autocabEarlyCrc.getCrc16Value())
    {
      return true;
    }
    else
    {
      return false;
    }
  }
}
