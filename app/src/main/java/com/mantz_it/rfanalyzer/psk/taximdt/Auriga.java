package com.mantz_it.rfanalyzer.psk.taximdt;
// Decode Auriga traffic //

// TODO Decode Auriga messages	

public class Auriga
{
  private String line[] = new String[50];
  private ExBitSet rdata = new ExBitSet();
  private boolean viewBinary;
  private boolean viewBadCrc;
  private boolean viewCrcWarnings;
  private int bcount;

  //getters and setters
  public String[] getLine()
  {
    return line;
  }

  public void setViewBinary(boolean viewBinary)
  {
    this.viewBinary = viewBinary;
  }

  public void setViewBadCrc(boolean viewBadCrc)
  {
    this.viewBadCrc = viewBadCrc;
  }

  public void setViewCrcWarnings(boolean viewCrcWarnings)
  {
    this.viewCrcWarnings = viewCrcWarnings;
  }

  public void setBcount(int bcount)
  {
    this.bcount = bcount;
  }

  //main decode method
  public void decode(ExBitSet unstuffedData, SystemInfo si)
  {
    // Create a new display stamp object //
    DisplayStamp timeStamp = new DisplayStamp();

    // Create a channel statistics object //
    ChannelStatistics channelStats = new ChannelStatistics();

    int actCrc = getCrc(unstuffedData);

    // First CRC check the message
    // Create a new CRC object
    Crc aurigaCrc = new Crc();

    // Set the CRC16 return value
    aurigaCrc.setCrc16Value(0xffff);

    int icount = 1;
    int byteIn = 0;
    for (int i = 0; i < (bcount - 16); i++)
    {
      byteIn <<= 1;
      byteIn = byteIn & 0xff;
      if (unstuffedData.get(i) == true)
      {
        byteIn++;
      }
      // Every 8 bits calculate the CRC //
      if (icount == 8)
      {
        aurigaCrc.ccitt_crc16(byteIn);
        icount = 1;
      }
      else
      {
        icount++;
      }//if
    }//for

    // Increment the good or bad Auriga packet counter //
    if (aurigaCrc.getCrc16Value() != actCrc)
    {
      channelStats.incBadAurigaPackets();
    }
    else
    {
      channelStats.incGoodAurigaPackets();
    }

    StringBuffer tmp = new StringBuffer();

    // Compare the CRC result with the actual inverted CRC
    if ((aurigaCrc.getCrc16Value() != actCrc) && !viewBadCrc)
    {
      // Does the user want to see bad CRC warnings //
      if (viewCrcWarnings)
      {
        tmp.append(timeStamp.getTimestamp());
        tmp.append(" Bad Auriga CRC ! ").append(aurigaCrc.getCrc16Value()).append("!=").append(actCrc);
        line[0] = tmp.toString();
      }
      return;
    }

    // Reverse all the bytes in the unstuffed data //
    reverse(unstuffedData);

    // Handle the display //
    // Create a new display stamp object //
    tmp.append(timeStamp.getTimestamp());

    // If the user wants to see bad data then at least mark it //
    if ((aurigaCrc.getCrc16Value() != actCrc) && viewBadCrc)
    {
      tmp.append(" (BAD CRC !)");
    }

    tmp.append(" Auriga ");

    if (unstuffedData.get(0))
    {
      tmp.append(" (Base) ");
    }
    else
    {
      tmp.append(" (Mobile) ");
    }

    //calculate the system code
    int sysCode = calcSysCode(unstuffedData);

    // Check if this user has been identified
    String sys_name = si.nameSearch(sysCode);
    if (sys_name == null)
    {
      tmp.append(": System ").append(sysCode);
    }
    else
    {
      tmp.append(": ").append(sys_name).append(" (").append(sysCode).append(")");
    }

    tmp.append(" : Length ").append(bcount / 8);

    //ID of the mobile unit
    int mobIdentity = calcMobIdent(rdata);
    tmp.append(" : Ident ").append(mobIdentity);
    // Create a user_statistics object and record this activity //
    // But don't bother if this is message to all mobiles (4095) //
    if (mobIdentity != 4095)
    {
      UserStatistics stats_object = new UserStatistics();
      stats_object.record_activity(sysCode, mobIdentity);
    }

    // Display the mystery 4 bits in binary
    //tmp.append(rdata.convertToString(16, 20));
    int type = 0;
    if (rdata.get(16))
    {
      type = type + 8;
    }
    if (rdata.get(17))
    {
      type = type + 4;
    }
    if (rdata.get(18))
    {
      type = type + 2;
    }
    if (rdata.get(19))
    {
      type = type + 1;
    }
    tmp.append(" (Type ");
    tmp.append(type);

    int stype = 0;
    // If length 7 and above display byte 4 in binary
    if (bcount > 48)
    {
      //tmp.append(" ");
      //tmp.append(rdata.convertToString(32, 40));
      if (rdata.get(32))
      {
        stype = stype + 128;
      }
      if (rdata.get(33))
      {
        stype = stype + 64;
      }
      if (rdata.get(34))
      {
        stype = stype + 32;
      }
      if (rdata.get(35))
      {
        stype = stype + 16;
      }
      if (rdata.get(36))
      {
        stype = stype + 8;
      }
      if (rdata.get(37))
      {
        stype = stype + 4;
      }
      if (rdata.get(38))
      {
        stype = stype + 2;
      }
      if (rdata.get(39))
      {
        stype = stype + 1;
      }

      tmp.append(" Subtype ");
      tmp.append(stype);
      tmp.append(")");
    }
    else
    {
      tmp.append(")");
    }

    // ACK
    if ((type == 8) && (bcount == 48))
    {
      tmp.append(" : ACK");
      line[0] = tmp.toString();
      return;
    }

    // Type 0 Subtype 1
    if ((type == 0) && (stype == 1))
    {
      line[0] = tmp.toString();
      handleAurigaType0Sub1(rdata);
      return;
    }

    // Type 0 Subtype 202
    if ((type == 0) && (stype == 202))
    {
      line[0] = tmp.toString();
      handleAurigaType0Sub202(rdata);
      return;
    }

    line[0] = tmp.toString();

    // Display unstuffed binary excluding the CRC //
    if (viewBinary)
    {
      line[2] = rdata.convertToString(0, (bcount - 16));
    }

    if ((bcount > 88) && (mobIdentity != 4095))
    {
      line[1] = displayAscii(40);
    }

    // If length 8 or above display the data as numbers
    if (bcount > 56)
    {
      line[3] = displayNums(40);
    }
  }

  private int getCrc(ExBitSet unstuffedData)
  {
    int crc = 0;

    // Calculate the numerical value of the 16 bits of the CRC inverted //
    if (!unstuffedData.get(bcount - 1))
    {
      crc = 1;
    }
    if (!unstuffedData.get(bcount - 2))
    {
      crc = crc + 2;
    }
    if (!unstuffedData.get(bcount - 3))
    {
      crc = crc + 4;
    }
    if (!unstuffedData.get(bcount - 4))
    {
      crc = crc + 8;
    }
    if (!unstuffedData.get(bcount - 5))
    {
      crc = crc + 16;
    }
    if (!unstuffedData.get(bcount - 6))
    {
      crc = crc + 32;
    }
    if (!unstuffedData.get(bcount - 7))
    {
      crc = crc + 64;
    }
    if (!unstuffedData.get(bcount - 8))
    {
      crc = crc + 128;
    }
    if (!unstuffedData.get(bcount - 9))
    {
      crc = crc + 256;
    }
    if (!unstuffedData.get(bcount - 10))
    {
      crc = crc + 512;
    }
    if (!unstuffedData.get(bcount - 11))
    {
      crc = crc + 1024;
    }
    if (!unstuffedData.get(bcount - 12))
    {
      crc = crc + 2048;
    }
    if (!unstuffedData.get(bcount - 13))
    {
      crc = crc + 4096;
    }
    if (!unstuffedData.get(bcount - 14))
    {
      crc = crc + 8192;
    }
    if (!unstuffedData.get(bcount - 15))
    {
      crc = crc + 16384;
    }
    if (!unstuffedData.get(bcount - 16))
    {
      crc = crc + 32768;
    }

    return crc;
  }

  private int calcSysCode(ExBitSet unstuffedData)
  {
    int sysCode = 0;

    // The first bit or unstuffed_data[0) is set if the tx is from the base
    // and clear if it is from a mobile
    // The next 15 bits of the packet is the system code //
    if (unstuffedData.get(1))
    {
      sysCode = 16384;
    }
    if (unstuffedData.get(2))
    {
      sysCode = sysCode + 8192;
    }
    if (unstuffedData.get(3))
    {
      sysCode = sysCode + 4096;
    }
    if (unstuffedData.get(4))
    {
      sysCode = sysCode + 2048;
    }
    if (unstuffedData.get(5))
    {
      sysCode = sysCode + 1024;
    }
    if (unstuffedData.get(6))
    {
      sysCode = sysCode + 512;
    }
    if (unstuffedData.get(7))
    {
      sysCode = sysCode + 256;
    }
    if (unstuffedData.get(8))
    {
      sysCode = sysCode + 128;
    }
    if (unstuffedData.get(9))
    {
      sysCode = sysCode + 64;
    }
    if (unstuffedData.get(10))
    {
      sysCode = sysCode + 32;
    }
    if (unstuffedData.get(11))
    {
      sysCode = sysCode + 16;
    }
    if (unstuffedData.get(12))
    {
      sysCode = sysCode + 8;
    }
    if (unstuffedData.get(13))
    {
      sysCode = sysCode + 4;
    }
    if (unstuffedData.get(14))
    {
      sysCode = sysCode + 2;
    }
    if (unstuffedData.get(15))
    {
      sysCode++;
    }

    return sysCode;
  }

  private int calcMobIdent(ExBitSet rdata)
  {
    // Experimental code to work out if the first 12 bits make up the mobile
    // ident //
    int mobId = 0;
    if (rdata.get(20))
    {
      mobId = 2048;
    }
    if (rdata.get(21))
    {
      mobId = mobId + 1024;
    }
    if (rdata.get(22))
    {
      mobId = mobId + 512;
    }
    if (rdata.get(23))
    {
      mobId = mobId + 256;
    }
    if (rdata.get(24))
    {
      mobId = mobId + 128;
    }
    if (rdata.get(25))
    {
      mobId = mobId + 64;
    }
    if (rdata.get(26))
    {
      mobId = mobId + 32;
    }
    if (rdata.get(27))
    {
      mobId = mobId + 16;
    }
    if (rdata.get(28))
    {
      mobId = mobId + 8;
    }
    if (rdata.get(29))
    {
      mobId = mobId + 4;
    }
    if (rdata.get(30))
    {
      mobId = mobId + 2;
    }
    if (rdata.get(31))
    {
      mobId++;
    }

    return mobId;
  }

  // Reverse the binary data received //
  private void reverse(ExBitSet udata)
  {
    int i;
    for (i = 0; i < (bcount - 16); i = i + 8)
    {
      rdata.set((i + 7), udata.get(i));
      rdata.set((i + 6), udata.get(i + 1));
      rdata.set((i + 5), udata.get(i + 2));
      rdata.set((i + 4), udata.get(i + 3));
      rdata.set((i + 3), udata.get(i + 4));
      rdata.set((i + 2), udata.get(i + 5));
      rdata.set((i + 1), udata.get(i + 6));
      rdata.set((i), udata.get(i + 7));
    }
  }

  // Display Auriga ASCII //
  private String displayAscii(int asciiStart)
  {
    String line = "";
    int i, cnt = 1;
    char ascii = 0;
    for (i = asciiStart; i < (bcount - 16); i++)
    {
      ascii <<= 1;
      if (rdata.get(i))
      {
        ascii++;
      }
      if (cnt == 8)
      {
        // Only display viewable characters //
        if ((ascii > 31) && (ascii < 127))
        {
          line = line + Character.toString(ascii);
        }
        // Handle special characters if the user wants to see them //
        cnt = 1;
        ascii = 0;
      }
      else
      {
        cnt++;
      }
    }
    return line;
  }

  // Display Auriga data as 8 bit numbers
  private String displayNums(int start)
  {
    String line = "";
    int i, ascii;
    for (i = start; i < (bcount - 16); i = i + 8)
    {
      ascii = returnAsciiValue(i, rdata);
      line = line + String.format("<%03d>", ascii);
    }
    return line;
  }

  // Find the position of any bytes holding the value 202
  private int findTwoOTwo(int start, ExBitSet bits)
  {
    int i;
    int ascii;
    for (i = start; i < (bcount - 16); i = i + 8)
    {
      ascii = returnAsciiValue(i, bits);
      if (ascii == 202)
      {
        return (i);
      }
    }
    return 0;
  }

  // Return an ASCII byte from a ExBitSet
  private int returnAsciiValue(int start, ExBitSet bits)
  {
    int i, cnt = 1;
    int ascii = 0;
    for (i = start; i < (start + 8); i++)
    {
      ascii <<= 1;
      if (bits.get(i))
      {
        ascii++;
      }
      if (cnt == 8)
      {
        return ascii;
      }
      else
      {
        cnt++;
      }
    }
    return 0;
  }

  // Return an Auriga character from an ExBitSet
  private String returnAurigaCharacter(int start, ExBitSet bits)
  {
    String ret;
    int ascii = returnAsciiValue(start, bits);
    // Handle special cases or return as a standard ASCII character
    if (ascii == 163)
    {
      ret = "£";
    }
    else if (ascii == 14)
    {
      ret = " ";
    }
    else
    {
      ret = Character.toString((char)ascii);
    }
    // Return this
    return ret;
  }

  // Decode Type 0 Subtype 1 messages
  private void handleAurigaType0Sub1(ExBitSet bits)
  {
    int i, bpos, cpos, dpos, epos, ascii, type, length1, length2, length3, jump;
    // Display the header	
    line[4] = "Header : ";
    // Find & display the header
    bpos = findTwoOTwo(40, bits);
    for (i = 40; i < (bpos); i = i + 8)
    {
      ascii = returnAsciiValue(i, bits);
      line[4] = line[4] + String.format("<%03d>", ascii);
    }
    // Find and display the first block
    ascii = returnAsciiValue(bpos, bits);
    line[5] = String.format("[%03d]", ascii);
    length1 = returnAsciiValue((bpos + 8), bits);
    type = returnAsciiValue((bpos + 16), bits);
    jump = (length1 * 8) + bpos;
    cpos = findTwoOTwo(jump, bits);
    line[5] = line[5] + String.format(" Type %03d", type);
    line[5] = line[5] + String.format(" Len %03d : ", length1);
    for (i = (bpos + 24); i < (cpos); i = i + 8)
    {
      ascii = returnAsciiValue(i, bits);
      line[5] = line[5] + String.format("<%03d>", ascii);
    }
    // Find and display the second block
    ascii = returnAsciiValue(cpos, bits);
    line[6] = String.format("[%03d]", ascii);
    length2 = returnAsciiValue((cpos + 8), bits);
    type = returnAsciiValue((cpos + 16), bits);
    jump = (length2 * 8) + cpos;
    dpos = findTwoOTwo(jump, bits);
    line[6] = line[6] + String.format(" Type %03d", type);
    line[6] = line[6] + String.format(" Len %03d : ", length2);
    for (i = (cpos + 24); i < dpos; i = i + 8)
    {
      // If type 144 this is a text message
      if (type == 144)
      {
        line[6] = line[6] + returnAurigaCharacter(i, bits);
      }
      else
      {
        ascii = returnAsciiValue(i, bits);
        line[6] = line[6] + String.format("<%03d>", ascii);
      }
    }
    // Find and display the third block
    epos = (bcount - 16);
    ascii = returnAsciiValue(dpos, bits);
    line[7] = String.format("[%03d]", ascii);
    length3 = returnAsciiValue((dpos + 8), bits);
    type = returnAsciiValue((dpos + 16), bits);
    line[7] = line[7] + String.format(" Type %03d", type);
    line[7] = line[7] + String.format(" Len %03d : ", length3);
    for (i = (dpos + 24); i < (epos); i = i + 8)
    {
      ascii = returnAsciiValue(i, bits);
      line[7] = line[7] + String.format("<%03d>", ascii);
    }

    // TODO : Handle the 4th block that may be here

  }

  // Decode Type 0 Subtype 202 messages
  private void handleAurigaType0Sub202(ExBitSet bits)
  {

    // Byte 1 of the payload is the payload byte count
    // Byte 2 appears to identify the payload type
    // 48 - ASCII ??

    // TODO: Decode type 0 subtype 202 messages

  }
}
