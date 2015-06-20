package com.mantz_it.rfanalyzer.psk.taximdt;

// Handle Autocab traffic //
public class Autocab
{
  public String line[] = new String[50];
  private boolean viewBinary;
  private boolean viewSpecialAscii;
  private boolean viewBadCrc;
  private boolean viewCrcWarnings;
  private boolean viewMultiLine;
  private boolean viewLinks;
  private int messageLength;
  private int messageBytes;
  private int systemCode;
  private int messageType;
  private int messageSubType;

  //getters and setters
  public void setSystemCode(int systemCode)
  {
    this.systemCode = systemCode;
  }

  public void setMessageLength(int messageLength)
  {
    this.messageLength = messageLength;
  }

  public void setViewBinary(boolean viewBinary)
  {
    this.viewBinary = viewBinary;
  }

  public void setViewSpecialAscii(boolean viewSpecialAscii)
  {
    this.viewSpecialAscii = viewSpecialAscii;
  }

  public void setViewBadCrc(boolean viewBadCrc)
  {
    this.viewBadCrc = viewBadCrc;
  }

  public void setViewCrcWarnings(boolean viewCrcWarnings)
  {
    this.viewCrcWarnings = viewCrcWarnings;
  }

  public void setViewMultiLine(boolean viewMultiLine)
  {
    this.viewMultiLine = viewMultiLine;
  }

  public int getMessageType()
  {
    return messageType;
  }

  public int getMessageSubType()
  {
    return messageSubType;
  }

  public void setViewLinks(boolean viewLinks)
  {
    this.viewLinks = viewLinks;
  }

  public boolean getViewLinks()
  {
    return viewLinks;
  }

  //main decode method
  public void decode(ExBitSet rawData, SystemInfo si)
  {
    int b2, b3, b4, b5, b6, b7, b8;
    int called = 0;
    int calling = 0;
    int actCrc = 0;

    // Create a new display stamp object //
    DisplayStamp timeStamp = new DisplayStamp();

    // Create a channel statistics object //
    ChannelStatistics channelStats = new ChannelStatistics();

    actCrc = getCrc(rawData);

    // First CRC check the message
    // Create a new CRC object
    Crc autocab_crc = new Crc();
    autocab_crc.setCrc16Value(0);

    int cnt = 1;
    int byteIn = 0;
    // Calculate the CRC the message should have
    for (int i = 16; i < (messageLength - 16); i++)
    {
      byteIn <<= 1;
      byteIn = byteIn & 0xff;

      if (rawData.get(i) == true)
      {
        byteIn++;
      }

      if (cnt == 8)
      {
        autocab_crc.ccitt_crc16(byteIn);
        cnt = 1;
      }
      else
      {
        cnt++;
      }
    }

    // If the CRC is good increment the good autocab packet counter else
    // increment the bad packets counter//
    if (autocab_crc.getCrc16Value() == actCrc)
    {
      channelStats.incGoodAutocabPacketsCounter();
    }
    else
    {
      channelStats.incBadAutocabPacketsCounter();
    }

    StringBuffer tmp = new StringBuffer();

    // Compare the actual and received CRC messages
    if ((autocab_crc.getCrc16Value() != actCrc) && (viewBadCrc == false))
    {
      // Does the user want to see bad CRC warnings //
      if (viewCrcWarnings == true)
      {
        tmp.append(timeStamp.getTimestamp());
        tmp.append(" Bad Autocab CRC !");
        line[0] = tmp.toString();
      }
      return;
    }

    // Add the number of bytes in this message to the total bytes variable
    channelStats.addBytesToTotal(messageLength / 8);

    // Unstuff the Autocab bits
    rawData = unstuffAutocab(rawData);

    // Byte 2 //
    b2 = headerByte(rawData, 2);
    // Byte 3 //
    b3 = headerByte(rawData, 3);
    // Byte 4 //
    b4 = headerByte(rawData, 4);
    // Byte 5 //
    b5 = headerByte(rawData, 5);
    // Byte 6 //
    b6 = headerByte(rawData, 6);
    // Byte 7 //
    b7 = headerByte(rawData, 7);
    // Byte 8 //
    b8 = headerByte(rawData, 8);
    // Calling address
    calling = (b3 << 8) + b4;
    // Called Address
    called = (b5 << 8) + b6;

    // Message type //
    messageType = b7;
    messageSubType = b8;

    // Message length
    messageBytes = headerByte(rawData, 10);

    // Create a user_statistics object and record this activity //
    // But don't bother if this is message to all mobiles (66535) //
    if ((called != 65535) && (called != 65025))
    {
      UserStatistics stats_object = new UserStatistics();
      stats_object.record_activity(calling, called);
    }

    // The display
    // Add a timestamp
    tmp.append(timeStamp.getTimestamp());
    // If the user wants to see bad data then at least mark it //
    if ((autocab_crc.getCrc16Value() != actCrc) && (viewBadCrc == true))
    {
      tmp.append(" (BAD CRC !)");
    }

    //		if (messageLength == 1000) {
    if (((headerByte(rawData, 0) << 8) + headerByte(rawData, 1)) == 1000)
    {
      tmp.append(" Autocab variant (0x").append(Integer.toHexString((int)systemCode));
    }
    else
    {
      tmp.append(" Autocab (0x").append(Integer.toHexString((int)systemCode));
    }

    // Check if this user has been identified
    String sys_name = si.nameSearch(calling);
    if (sys_name == null)
    {
      tmp.append(") : System ").append(calling);
    }
    else
    {
      tmp.append(") : ").append(sys_name).append(" (").append(calling).append(")");
    }

    //		tmp.append(" : Ident ").append(called);
    tmp.append(" : Ident Þbß").append(called).append("Þ/bß");

    // Message Type //
    tmp.append(" : Message Type ").append(messageType);

    // Handle the different message types //

    // Type 0
    if (messageType == 0)
    {
      messageSubType = b8;
      // ACK
      if (messageSubType == 0)
      {
        tmp.append(" - ACK");
      }
      // BCAST
      else if (called == 65535)
      {
        tmp.append(" - BCAST (Sub Type ").append(b8).append(")");
        //				if (messageSubType == 10)handle_autocab_t0_bcast_s10(rawData);
        if (messageSubType == 10)
        {
          handle_autocab_t0_bcast_s42(rawData);
        }
        if (messageSubType == 42)
        {
          handle_autocab_t0_bcast_s42(rawData);
        }
      }
      // Other
      else
      {
        tmp.append(handle_autocab_t0_nonbcast(rawData));
      }
    }

    // Type 1 //
    if (messageType == 1)
    {
      if (called == 65025)
      {
        tmp.append(" - BCAST (Sub Type ").append(b8).append(")");
      }
      if (messageSubType == 72)
      {
        handle_autocab_t0_bcast_s42(rawData);
      }
      else
      {
        tmp.append(handle_autocab_t1(rawData));
      }
    }

    // Type 4 //
    if (messageType == 4)
    {
      tmp.append(handle_autocab_t4(rawData));
    }

    line[0] = tmp.toString();

    // Display this in binary form if that is what the user wants
    // Note the 16 CRC bits aren't displayed
    if (viewBinary == true)
    {
      line[1] = rawData.convertToString(0, (messageLength - 16));
    }
  }

  // Display the contents of type 0 subtype 42 messages
  private void handle_autocab_t0_bcast_s42(ExBitSet bits)
  {
    // Display the type and length of the message //
    //int stype = return_byte(bits, 88 + offset);
    //int mlen = return_byte(bits, 80 + offset);
    //StringBuffer tmp = new StringBuffer(String.format(" (%03d,%03d)", mlen, stype));

    //int plotCount = return_byte(bits, 96 + offset);
    //		int byteContent[] = new int [250];
    int fourBit[] = new int[4];
    int counter = 0;
    int lineNumber = 2;
    int i;

/*		for (i = 2; i < (messageBytes - 3); i = i + 1) {
			// The plot number //
			byteContent[counter] = messageByte(bits, i);
			if (byteContent[counter] != 239) counter ++;
		}*/

    for (i = 2; i < (messageBytes - 3); i = i + 3)
    {
      // Number of cars on this plot //
      fourBit[0] = messageByte(bits, i + 1) & 240;
      fourBit[0] = fourBit[0] >> 4;
      // Number of jobs available now
      fourBit[1] = messageByte(bits, i + 1) & 15;
      // Number of jobs available in 15 minutes
      fourBit[2] = messageByte(bits, i + 2) & 240;
      fourBit[2] = fourBit[2] >> 4;
      // Number of jobs available in 30 minutes
      fourBit[3] = messageByte(bits, i + 2) & 15;

      // Display this info
      if ((fourBit[0] > 0) || (fourBit[1] > 0) || (fourBit[2] > 0) || (fourBit[3] > 0))
      {
        line[lineNumber] = String
            .format("Plot %03d - Cars %02d : Jobs Now %02d : Jobs 15 Mins %02d : Jobs 30 Mins %02d", messageByte(bits, i), fourBit[0], fourBit[1], fourBit[2], fourBit[3]);

        lineNumber++;
        if (lineNumber == 50)
        {
          return;
        }
      }
    }

    return;
  }

  // Display the contents of type 0 subtype 10 messages
  private void handle_autocab_t0_bcast_s10(ExBitSet bits)
  {
    // Display the type and length of the message //
    //int stype = return_byte(bits, 88 + offset);
    //int mlen = return_byte(bits, 80 + offset);
    //StringBuffer tmp = new StringBuffer(String.format(" (%03d,%03d)", mlen, stype));

    //int plotCount = return_byte(bits, 96 + offset);
    //		int byteContent[] = new int [250];
    int counter = 0;
    int lineNumber = 2;
    int i;

    line[lineNumber] = "";

    for (i = 1; i < (messageBytes); i = i + 1)
    {
      // The plot number //
      //			byteContent[counter] = return_byte(bits, i);
      line[lineNumber] = line[lineNumber] + String.format("<%03d>", messageByte(bits, i));
      counter++;
      if (counter % 20 == 0)
      {
        lineNumber++;
        line[lineNumber] = "";
      }
    }

    return;
  }

  // Handle Autocab Type 0 Sub type 132 messages //
  private String handle_autocab_t0_nonbcast(ExBitSet bits)
  {
    // Type 0 Sub Type 132 messages
    // Byte 09 - Unknown always 0
    // Byte 10 - Number of bytes in the message
    // Byte 11 - Seems to indicate a further type to the message

    // Further type 102 contains no digits and may be key press info
    // Further type 148 is string of numbers with an unknown purpose
    // Further type 150 has an unknown purpose
    // Further type 241 is a 3 digit number possibly a job number
    // Further type 242 is a status message
    // Further type 255 has an unknown purpose

    int stype = headerByte(bits, 8);
    int mtype = messageByte(bits, 0);
    StringBuffer tmp = new StringBuffer(String.format(" - (Sub Type=%03d Further Type=%03d) ", stype, mtype));
    tmp.append(" ");

    // Further type 102 + 150 + 255 //
    if ((mtype == 102) || (mtype == 150) || (mtype == 255))
    {
      int a;
      int c;
      tmp.append(String.format("Plot %03d  ", messageByte(bits, 17)));
      for (a = 1; a < messageBytes; a = a + 1)
      {
        c = messageByte(bits, a);
        tmp.append(String.format("%03d ", c));
      }
    }

    // Further type 148
    if (mtype == 148)
    {
      int a;
      int c;
      for (a = 1; a < (messageBytes); a = a + 1)
      {
        c = messageByte(bits, a);
        // Display only numbers
        if ((c > 47) && (c < 58))
        {
          tmp.append(Character.toString((char)c));
        }
      }
    }

    // Further type 241 //
    if (mtype == 241)
    {
      //tmp.delete(0,tmp.length());
      int c1 = messageByte(bits, 1);
      int c2 = messageByte(bits, 2);
      int c3 = messageByte(bits, 3);
      tmp.append(Character.toString((char)c1));
      tmp.append(Character.toString((char)c2));
      tmp.append(Character.toString((char)c3));

      tmp.append(" ");
      int a;
      int c;
      for (a = 4; a < (messageBytes); a = a + 1)
      {
        c = messageByte(bits, a);
        tmp.append(String.format("<%03d>", c));
      }
    }

    // Further type 242 //
    if (mtype == 242)
    {
      tmp.delete(0, tmp.length());
      tmp.append(" - ");
      int odigit = messageByte(bits, 2);
      int tdigit = messageByte(bits, 3);
      String val = Character.toString((char)odigit);
      val = val + Character.toString((char)tdigit);
      // Status meanings
      if (val.equals("00"))
      {
        tmp.append("Recall Last Message");
      }
      if (val.equals("77"))
      {
        tmp.append("Soon to Clear");
      }
      if (val.equals("78"))
      {
        tmp.append("Long Break");
      }
      if (val.equals("82"))
      {
        tmp.append("Short Break");
      }
      if (val.equals("81"))
      {
        tmp.append("Finish Break");
      }
      if (val.equals("86"))
      {
        tmp.append("Yes");
      }
      if (val.equals("87"))
      {
        tmp.append("No");
      }
      if (val.equals("90"))
      {
        tmp.append("Voice Request");
      }
      if (val.equals("91"))
      {
        tmp.append("Information");
      }
      if (val.equals("92"))
      {
        tmp.append("Direction");
      }
      if (val.equals("93"))
      {
        tmp.append("Finish Work for the Day");
      }
      if (val.equals("94"))
      {
        tmp.append("Waiting Outside");
      }
      if (val.equals("95"))
      {
        tmp.append("Clear");
      }
      if (val.equals("96"))
      {
        tmp.append("Ringback");
      }
      if (val.equals("97"))
      {
        tmp.append("Recover Job");
      }
      if (val.equals("98"))
      {
        tmp.append("No Job");
      }
      if (val.equals("83"))
      {
        tmp.append("Bid");
      }
      if (val.equals("88"))
      {
        tmp.append("Mobile");
      }
      if (val.equals("99"))
      {
        tmp.append("Emergency");
      }
    }

    return tmp.toString();
  }

  // Handle Autocab Type 1 messages //
  private String handle_autocab_t1(ExBitSet bits)
  {

    int a;
    int ascii;
    int subType = headerByte(bits, 8);
    //		int length = return_byte(bits, 80);

    // Length 5 has an unknown purpose (bytes 3 & 4 are current time)
    // Length 11 consists of numbers only
    // Lengths > 11 text

    StringBuffer tmp = new StringBuffer(" : ");
    tmp.append(String.format("Length %d : ", messageBytes));

    // Length 5
    if (messageBytes == 5)
    {
      int u1 = messageByte(bits, 0);
      int u2 = messageByte(bits, 1);
      int u3 = messageByte(bits, 2);
      int hour = messageByte(bits, 3);
      int minute = messageByte(bits, 4);
      // Display the time
      tmp.append(String.format("%02d", hour));
      tmp.append(":");
      tmp.append(String.format("%02d ", minute));
      // Display the unknown bytes
      tmp.append(String.format("<%03d>", u1));
      tmp.append(String.format(" Plot %03d ", u2));
      tmp.append(String.format("Queue# %d", u3));
      //        	tmp.append(String.format("<%03d>",u3));
      return tmp.toString();
    }

    // Length 11
    if ((messageBytes == 11) && (subType == 8))
    {
      int hour = messageByte(bits, 3);
      int minute = messageByte(bits, 4);
      // Display the time
      tmp.append(String.format("%02d", hour));
      tmp.append(":");
      tmp.append(String.format("%02d", minute));
      tmp.append(" ");
      displayAsciiLine(bits, 1, 5, messageBytes - 5, 0);
      return tmp.toString();
    }

/*        // Display the message
        for (a=1; a<=messageBytes; a=a+1)	{
 	    ascii=messageByte(bits,a);
            if ((ascii>31) && (ascii<123)) tmp.append(Character.toString((char) ascii));
            }	*/
    displayAsciiLine(bits, 1, 0, messageBytes, 0);

    return tmp.toString();
  }

  // Handle Autocab Type 4 messages //
  private String handle_autocab_t4(ExBitSet bits)
  {
    int b9 = headerByte(bits, 8);    // Byte 9 //
    int b10 = headerByte(bits, 9);    // Byte 10 //
    int b11 = headerByte(bits, 10);    // Byte 11 - message length
    int b12 = messageByte(bits, 0);    // Byte 12 - the sub type
    int b13 = messageByte(bits, 1);    // Byte 13 //
    int b14 = messageByte(bits, 2);    // Byte 14 //
    int b15 = messageByte(bits, 3);    // Byte 15 //
    int b16 = messageByte(bits, 4);    // Byte 16 //
    int b17 = messageByte(bits, 5);    // Byte 17 //

    messageSubType = b12;

    // Display the sub type on line 0 //
    StringBuffer tmp = new StringBuffer(" : Sub Type ");
    tmp.append(messageSubType);

    // Sub type 1 - Job details //
    if (messageSubType == 1)
    {
      if (messageByte(bits, messageBytes - 19) == 0)
      {
        if (getViewLinks() == true)
        {
          tmp.append(" Þa href='http://www.multimap.com/map/browse.cgi?X=");
          tmp.append(String.format("%d&Y=",
              (messageByte(bits, messageBytes - 15) << 24) + (messageByte(bits, messageBytes - 16) << 16) + (messageByte(bits, messageBytes - 17) << 8) + messageByte(bits,
                  messageBytes - 18)));
          tmp.append(String.format("%d'ßFROMÞ/aß ",
              (messageByte(bits, messageBytes - 11) << 24) + (messageByte(bits, messageBytes - 12) << 16) + (messageByte(bits, messageBytes - 13) << 8) + messageByte(bits,
                  messageBytes - 14)));
          tmp.append(" Þa href='http://www.multimap.com/map/browse.cgi?X=");
          tmp.append(String.format("%d&Y=",
              (messageByte(bits, messageBytes - 7) << 24) + (messageByte(bits, messageBytes - 8) << 16) + (messageByte(bits, messageBytes - 9) << 8) + messageByte(bits,
                  messageBytes - 10)));
          tmp.append(String.format("%d'ßDESTÞ/aß ",
              (messageByte(bits, messageBytes - 3) << 24) + (messageByte(bits, messageBytes - 4) << 16) + (messageByte(bits, messageBytes - 5) << 8) + messageByte(bits,
                  messageBytes - 6)));
        }
        displayAsciiLine(bits, 2, 0, messageBytes - 21, 1);
      }
      else if (messageByte(bits, messageBytes - 13) == 0)
      {
        if (getViewLinks() == true)
        {
          tmp.append(" Þa href='http://www.multimap.com/map/browse.cgi?X=");
          tmp.append(String.format("%d&Y=",
              (messageByte(bits, messageBytes - 7) << 24) + (messageByte(bits, messageBytes - 8) << 16) + (messageByte(bits, messageBytes - 9) << 8) + messageByte(bits,
                  messageBytes - 10)));
          tmp.append(String.format("%d'ßFROMÞ/aß ",
              (messageByte(bits, messageBytes - 3) << 24) + (messageByte(bits, messageBytes - 4) << 16) + (messageByte(bits, messageBytes - 5) << 8) + messageByte(bits,
                  messageBytes - 6)));
        }
        displayAsciiLine(bits, 2, 0, messageBytes - 13, 1);
      }
      else
      {
        displayAsciiLine(bits, 2, 0, messageBytes - 4, 1);
      }
    }

    if (messageSubType == 2)
    {
      displayAsciiLine(bits, 2, 2, messageBytes - 2, 1);
    }

    // Sub type 6 - Unknown //
    if (messageSubType == 6)
    {
      // Display the mystery bytes //
      tmp.append(String.format(" (%03d,%03d,%03d,%03d,%03d)", b9, b10, b11, b12, b13));
    }

    // Sub type 32 - Channel control messages //
    if (messageSubType == 32)
    {
      // Display the mystery bytes //
      tmp.append(String.format(" (%03d,%03d,%03d,%03d,%03d,%03d,%03d,%03d,%03d)",
          b9, b10, b11, b12, b13, b14, b15, b16, b17));

      // Now show the text line //
      displayAsciiLine(bits, 2, 7, messageBytes - 7, 32);
    }

    return tmp.toString();
  }

  private int getCrc(ExBitSet rawData)
  {
    // CRC check the message
    // Find the messages actual CRC value
    int crc = 0;
    if (rawData.get(messageLength - 1) == true)
    {
      crc = 1;
    }
    if (rawData.get(messageLength - 2) == true)
    {
      crc = crc + 2;
    }
    if (rawData.get(messageLength - 3) == true)
    {
      crc = crc + 4;
    }
    if (rawData.get(messageLength - 4) == true)
    {
      crc = crc + 8;
    }
    if (rawData.get(messageLength - 5) == true)
    {
      crc = crc + 16;
    }
    if (rawData.get(messageLength - 6) == true)
    {
      crc = crc + 32;
    }
    if (rawData.get(messageLength - 7) == true)
    {
      crc = crc + 64;
    }
    if (rawData.get(messageLength - 8) == true)
    {
      crc = crc + 128;
    }
    if (rawData.get(messageLength - 9) == true)
    {
      crc = crc + 256;
    }
    if (rawData.get(messageLength - 10) == true)
    {
      crc = crc + 512;
    }
    if (rawData.get(messageLength - 11) == true)
    {
      crc = crc + 1024;
    }
    if (rawData.get(messageLength - 12) == true)
    {
      crc = crc + 2048;
    }
    if (rawData.get(messageLength - 13) == true)
    {
      crc = crc + 4096;
    }
    if (rawData.get(messageLength - 14) == true)
    {
      crc = crc + 8192;
    }
    if (rawData.get(messageLength - 15) == true)
    {
      crc = crc + 16384;
    }
    if (rawData.get(messageLength - 16) == true)
    {
      crc = crc + 32768;
    }

    return crc;
  }

  // Return a byte from the raw data binary //

  private int headerByte(ExBitSet bits, int num)
  {
    if (num > 10)
    {
      System.out.println(String.format("Bad header byte %d !", num));
    }
    return returnByte(bits, num * 8);
  }

  private int messageByte(ExBitSet bits, int num)
  {
    if (num < 0)
    {
      System.out.println(String.format("Bad message byte %d !", num));
      return 123;
    }
    return returnByte(bits, (num + 11) * 8);
  }

  private int returnByte(ExBitSet bits, int start)
  {
    int b = 0;
    for (int i = 0; i < 8; i++)
    {
      if (bits.get(start + i))
      {
        b = (b | 1);
      }
      if (i < 7)
      {
        b = b << 1;
      }
    }
    return b;
  }

/*	private int return_byte(ExBitSet bits, int start) {
		int b = 0;
		if (bits.get(start) == true)
			b = 128;
		if (bits.get(start + 1) == true)
			b = b + 64;
		if (bits.get(start + 2) == true)
			b = b + 32;
		if (bits.get(start + 3) == true)
			b = b + 16;
		if (bits.get(start + 4) == true)
			b = b + 8;
		if (bits.get(start + 5) == true)
			b = b + 4;
		if (bits.get(start + 6) == true)
			b = b + 2;
		if (bits.get(start + 7) == true)
			b++;
		return b;
	}*/

  // Write an ASCII message to a display line //
  private void displayAsciiLine(ExBitSet bits, int lineNos, int asciiStart, int count, int sType)
  {
    int i, ascii;

    // Make sure the line is clear //
    // But if the type is 99 don't do this //
    if (sType != 99)
    {
      line[lineNos] = "";
    }
    for (i = asciiStart; i < (asciiStart + count); i = i + 1)
    {
      //System.out.println(String.format("%d %02X",i,messageByte(bits,i)));
      // Check we aren't trying to receive more characters than the
      // message contains //
      if (i > (messageBytes))
      {
        return;
      }

      // Get the ascii character from the raw data //
      ascii = messageByte(bits, i);
/*
			// Look for the special end of message characters //
			if ((ascii == 19) || (ascii == 255))
				return;

			// If this isn't a sub type 32 message then a 0 signals the end //
			if ((sType != 32) && (ascii == 0))
				return;*/

      // If the user wants messages displayed across multiple lines then
      // do this
      // whenever an <LF> character is received
      if ((ascii == 10) && (lineNos < 19) && (viewMultiLine == true))
      {
        lineNos++;
        line[lineNos] = "";
      }

      // Only display viewable characters //
      if ((ascii > 31) && (ascii < 127))
      {
        line[lineNos] = line[lineNos] + Character.toString((char)ascii);
      }

      if (ascii == 0)
      {
        line[lineNos] = line[lineNos] + Character.toString((char)133);
      }

      // Handle special characters if the user wants to see them //
      if (viewSpecialAscii == true)
      {
        if (ascii == 3)
        {
          line[lineNos] = line[lineNos] + "<ETX>";
        }
        if (ascii == 6)
        {
          line[lineNos] = line[lineNos] + "<ACK>";
        }
        if (ascii == 7)
        {
          line[lineNos] = line[lineNos] + "<BELL>";
        }
        if (ascii == 10)
        {
          line[lineNos] = line[lineNos] + "<LF>";
        }
        if (ascii == 13)
        {
          line[lineNos] = line[lineNos] + "<CR>";
        }
      }
    }
  }

  // This method strips out 0xef from the messages if it is followed by 0x02 0x03 0x04 or 0xef
  private ExBitSet unstuffAutocab(ExBitSet bitsIn)
  {

    ExBitSet bitsOut = new ExBitSet();
    int inBitCount = messageLength;
    int a = 0, b = 0, curByte, nextByte;
    int aBit, bBit, max;
    boolean stuff = false;

    while (a < (inBitCount - 8))
    {
      curByte = returnByte(bitsIn, a);
      nextByte = returnByte(bitsIn, a + 8);
      if ((curByte == 0xef) && ((nextByte == 0x02) || (nextByte == 0x03) || (nextByte == 0x04) || (nextByte == 0xef)))
      {
        stuff = true;
      }
      else
      {
        stuff = false;
      }
      // Copy 8 bits from bitsIn into bitsOut
      if (stuff == false)
      {
        bBit = b;
        max = a + 8;
        for (aBit = a; aBit < max; aBit++)
        {
          bitsOut.set(bBit, bitsIn.get(aBit));
          bBit++;
        }
        b = b + 8;
      }
      a = a + 8;
    }
    // All done
    return bitsOut;
  }
}
