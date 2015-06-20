package com.mantz_it.rfanalyzer.psk.taximdt;

/**
 * @author Andy Class to handle the various packet types
 */
public class TaxiMdtDecoder
{
  public static final int BUFFER_SIZE = 2048;//1024;

  public ExBitSet raw_bits = new ExBitSet();
  public boolean sync_hunt = false;
  public boolean preamble_hunt = false;
  public boolean decode_mode = true;
  public long sync_rxed = 0;
  public long preamble_rxed = 0;
  public byte preamble_hunt_status = 0;
  public int bits_rxed = -1;
  public int message_handled = 0;
  public int message_length = 0;
  public int vertical_scrollbar_value = 0;
  public int horizontal_scrollbar_value = 0;
  public boolean view_binary = false;
  public int raw_length = 0;
  public boolean view_special_ascii = false;
  public boolean view_bad_crc = false;
  public boolean view_multi_lines = false;
  public boolean view_links = false;
  public boolean clear_screen_now = false;
  public boolean view_no_autocab = false;
  public boolean view_no_auriga = false;
  public boolean view_bad_crc_warnings = true;
  public boolean generate_channel_statistics = false;
  public boolean view_autocab_t0_ack = true;
  public boolean view_autocab_t0_bcast = true;
  public boolean view_autocab_t0_s132 = true;
  public boolean view_autocab_t1 = true;
  public boolean view_autocab_t4_s1 = true;
  public boolean view_autocab_t4_s6 = true;
  public boolean view_autocab_t4_s32 = true;
  private SystemInfo info;
  private static byte[] buffer = null;

  public TaxiMdtDecoder(SystemInfo info)
  {
    this.info = info;
    buffer = new byte[BUFFER_SIZE];
  }

  // Handle Autocab 0x4c7d and 0x7d4c messages
  public String[] handle_autocab(boolean bit, int system_code)
  {
    if (bits_rxed == -1)
    {
      sync_rxed = 0;
      message_handled = system_code;
      bits_rxed = 0;
      message_length = 0;
      return null;
    }
    // Put the new bit into the buffer
    try
    {
      raw_bits.set(bits_rxed, bit);
    }
    catch (Exception e)
    {
      System.out.println("\nOverflow in handle_autocab ");
      System.out.println(Integer.toString(bits_rxed));
      System.out.println(Integer.toString(message_length));
      clear_ready_for_next_msg();
      return null;
    }
    // Increment the received bits counter
    bits_rxed++;
    // If we have less than 16 bits received then return now //
    // as we don't have the header yet //
    if (bits_rxed < 16)
    {
      return null;
    }
    // If we have enough bits calculate the message length
    if (bits_rxed == 16)
    {
      if (raw_bits.get(8))
      {
        message_length = 128;
      }
      if (raw_bits.get(9))
      {
        message_length = message_length + 64;
      }
      if (raw_bits.get(10))
      {
        message_length = message_length + 32;
      }
      if (raw_bits.get(11))
      {
        message_length = message_length + 16;
      }
      if (raw_bits.get(12))
      {
        message_length = message_length + 8;
      }
      if (raw_bits.get(13))
      {
        message_length = message_length + 4;
      }
      if (raw_bits.get(14))
      {
        message_length = message_length + 2;
      }
      if (raw_bits.get(15))
      {
        message_length++;
      }
      raw_length = message_length;
      message_length = (message_length * 8) + 16;
      // If the message length is less than 80 bits this isn't a real
      // packet
      // so can be ignored
      if (message_length < 80)
      {
        clear_ready_for_next_msg();
        return null;
      }
    }
    // If we have len bits received then display them
    if (message_length == bits_rxed)
    {
      // Don't view any Autocab messages //
      if (view_no_autocab)
      {
        clear_ready_for_next_msg();
        return null;
      }
      // Create an Autocab object //
      Autocab autocab_object = new Autocab();

      // Pass the object the info it needs to decode the data
      autocab_object.setMessageLength(message_length);
      autocab_object.setSystemCode(system_code);
      autocab_object.setViewBinary(view_binary);
      autocab_object.setViewBadCrc(view_bad_crc);
      autocab_object.setViewCrcWarnings(view_bad_crc_warnings);
      autocab_object.setViewSpecialAscii(view_special_ascii);
      autocab_object.setViewMultiLine(view_multi_lines);
      autocab_object.setViewLinks(view_links);

      // Decode the data //
      autocab_object.decode(raw_bits, this.info);
      clear_ready_for_next_msg();
      // Message filtering //
      int messageType = autocab_object.getMessageType();
      int messageSubType = autocab_object.getMessageSubType();
      // Type 0
      if (!view_autocab_t0_ack
          && (messageType == 0)
          && (messageSubType == 0))
      {
        return null;
      }
      if (!view_autocab_t0_bcast
          && (messageType == 0)
          && ((messageSubType == 10) || (messageSubType == 42)))
      {
        return null;
      }
      if (!view_autocab_t0_s132
          && (messageType == 0)
          && (messageSubType == 132))
      {
        return null;
      }
      // Type 1
      if (!view_autocab_t1
          && (messageType == 1))
      {
        return null;
      }
      // Type 4
      if (!view_autocab_t4_s1
          && (messageType == 4)
          && (messageSubType == 1))
      {
        return null;
      }
      if (!view_autocab_t4_s6
          && (messageType == 4)
          && (messageSubType == 6))
      {
        return null;
      }
      if (!view_autocab_t4_s32
          && (messageType == 4)
          && (messageSubType == 32))
      {
        return null;
      }

      // Display the message //
      return autocab_object.line;
      //			display_view.add_array(autocab_object.line);
    }
    return null;
  }

  // Handle Auriga messages
  public String[] handle_auriga(boolean bit)
  {
    if (bits_rxed == -1)
    {
      sync_rxed = 0;
      message_handled = 0xeff7;
      bits_rxed = 0;
      return null;
    }
    // Put the new bit into the buffer
    try
    {
      raw_bits.set(bits_rxed, bit);
    }
    catch (Exception e)
    {
      System.out.println("\nOverflow in handle_auriga ");
      System.out.println(Integer.toString(bits_rxed));
      System.out.println(Integer.toString(message_length));
      clear_ready_for_next_msg();
      return null;
    }
    // Increment the received bits counter
    bits_rxed++;
    // If less than 32 bits received just return as we haven't enough for a
    // proper frame
    if (bits_rxed < 32)
    {
      return null;
    }
    // Look for the end flag 01111110 //
    if (!raw_bits.get(bits_rxed - 1)
        && raw_bits.get(bits_rxed - 2)
        && raw_bits.get(bits_rxed - 3)
        && raw_bits.get(bits_rxed - 4)
        && raw_bits.get(bits_rxed - 5)
        && raw_bits.get(bits_rxed - 6)
        && raw_bits.get(bits_rxed - 7)
        && !raw_bits.get(bits_rxed - 8))
    {
      ExBitSet unstuffed_data = new ExBitSet();
      // Unstuff the data //
      unstuffed_data = raw_bits.unstuff(bits_rxed);
      // Does the user want to display Auriga messages //
      if (view_no_auriga)
      {
        clear_ready_for_next_msg();
        return null;
      }
      // Create a new Auriga object to decode the data //
      Auriga auriga_object = new Auriga();

      // Give the object the data it needs //
      auriga_object.setBcount(raw_bits.getBitCount());
      auriga_object.setViewBinary(view_binary);
      auriga_object.setViewBadCrc(view_bad_crc);
      auriga_object.setViewCrcWarnings(view_bad_crc_warnings);

      // Decode the data //
      auriga_object.decode(unstuffed_data, this.info);

      // Display the message //
      return auriga_object.getLine();
      //			display_view.add_array(auriga_object.getLine());
      //			clear_ready_for_next_msg();
    }
    return null;
  }

  // The Autocab (early) data gathering routine
  public String[] handle_autocab_e(boolean bit)
  {
    if (bits_rxed == -1)
    {
      sync_rxed = 0;
      message_handled = 0xb433;
      bits_rxed = 0;
      message_length = 128;
      return null;
    }
    // Put the new bit into the buffer
    try
    {
      raw_bits.set(bits_rxed, bit);
    }
    catch (Exception e)
    {
      System.out.println("\nOverflow in handle_autocab_e ");
      System.out.println(Integer.toString(bits_rxed));
      System.out.println(Integer.toString(message_length));
      clear_ready_for_next_msg();
      return null;
    }
    // Increment the received bits counter
    bits_rxed++;
    // Grab 128 bits of Autocab data //
    if (bits_rxed == (message_length + 1))
    {
      // If this is the 1st block then calculate the total length of the
      // message //
      // from the 3rd byte //
      if (message_length == 128)
      {
        int tlen = 0;
        if (raw_bits.get(16))
        {
          tlen = 128;
        }
        if (raw_bits.get(17))
        {
          tlen = tlen + 64;
        }
        if (raw_bits.get(18))
        {
          tlen = tlen + 32;
        }
        if (raw_bits.get(19))
        {
          tlen = tlen + 16;
        }
        if (raw_bits.get(20))
        {
          tlen = tlen + 8;
        }
        if (raw_bits.get(21))
        {
          tlen = tlen + 4;
        }
        if (raw_bits.get(22))
        {
          tlen = tlen + 2;
        }
        if (raw_bits.get(23))
        {
          tlen++;
        }
        // tlen contains the number of blocks and each block contains 64
        // bits //
        message_length = tlen * 64;
        // If message_length is greater than 16384 then there isn't
        // enough buffer //
        if (message_length > 16384)
        {
          clear_ready_for_next_msg();
          return null;
        }
        // If more blocks are needed then go back for them //
        if (tlen != 2)
        {
          return null;
        }
      }
      // Create a new Autocab object to decode the data //
      AutocabEarly autocab_e_object = new AutocabEarly();
      // Divide by 64 to calculate the number of blocks //
      autocab_e_object.block_count = (message_length / 64);
      autocab_e_object.view_binary = view_binary;
      autocab_e_object.view_bad_crc = view_bad_crc;
      autocab_e_object.view_special_ascii = view_special_ascii;
      // Decode the data //
      autocab_e_object.decode(raw_bits, this.info);
      // Display the info //
      return autocab_e_object.line;
      //			display_view.add_array(autocab_e_object.line);
      //			clear_ready_for_next_msg();
    }
    return null;
  }

  // Handle the unknown 0xc040 messages
  public String[] handle_c040(boolean bit, int system_code)
  {
    String[] ret = {"Sync 0xc040 Detected"};
    return (ret);
    //		display_view.add_line("Sync 0xc040 Detected");
    //		clear_ready_for_next_msg();
  }

  // Handle the unknown 0x007e headed messages
  public String[] handle_007e(boolean bit, int system_code)
  {
    if (bits_rxed == -1)
    {
      sync_rxed = 0;
      message_handled = 0x007e;
      bits_rxed = 0;
      return null;
    }
    // Put the new bit into the buffer
    try
    {
      raw_bits.set(bits_rxed, bit);
    }
    catch (Exception e)
    {
      System.out.println("\nOverflow in handle_007e ");
      System.out.println(Integer.toString(bits_rxed));
      System.out.println(Integer.toString(message_length));
      clear_ready_for_next_msg();
      return null;
    }
    // Increment the received bits counter
    bits_rxed++;

    // If less than 16 bits received just return as we haven't enough for a
    // proper frame
    if (bits_rxed < 16)
    {
      return null;
    }
    // Look for the end flag 01111110 //
    if ((!raw_bits.get(bits_rxed - 1))
        && (raw_bits.get(bits_rxed - 2))
        && (raw_bits.get(bits_rxed - 3))
        && (raw_bits.get(bits_rxed - 4))
        && (raw_bits.get(bits_rxed - 5))
        && (raw_bits.get(bits_rxed - 6))
        && (raw_bits.get(bits_rxed - 7))
        && (!raw_bits.get(bits_rxed - 8)))
    {
      ExBitSet unstuffed_data = new ExBitSet();
      // Unstuff the data //
      unstuffed_data = raw_bits.unstuff(bits_rxed);

      Unknown007e object007e = new Unknown007e();
      object007e.decode(unstuffed_data);
      return object007e.line;
      //			display_view.add_array(object007e.line);
      //			clear_ready_for_next_msg();
    }
    return null;
  }

  // The main decode mode routine
  public void decode(boolean in, int whichChannel)
  {
    String[] decodedMsg = null;
    // Still looking for a sync word
    if (message_handled == 0)
    {
      // Rotate the sync word 1 bit to the left
      sync_rxed <<= 1;
      // We only need 32 bits of this
      sync_rxed = sync_rxed & 0xffffffffL;
      // Add the latest bit
      if (in)
      {
        sync_rxed++;
      }
      // Look for recognised sync words
      if (sync_rxed == 0xaeff7e7eL)
      {
        decodedMsg = handle_auriga(in);
      }
      if ((sync_rxed & 0xffffff) == 0xaa4c7d)
      {
        decodedMsg = handle_autocab(in, 0x4c7d);
      }
      if ((sync_rxed & 0xffffff) == 0xaa7d4c)
      {
        decodedMsg = handle_autocab(in, 0x7d4c);
      }
      if ((sync_rxed & 0xffffff) == 0xaab433)
      {
        decodedMsg = handle_autocab_e(in);
      }
      if ((sync_rxed & 0xffffff) == 0xaac040)
      {
        decodedMsg = handle_c040(in, 0xc040);
      }
      if ((sync_rxed & 0xffffff) == 0xaa007e)
      {
        decodedMsg = handle_007e(in, 0x007e);
      }
    }
    else
    {
      // 0x4c7d Autocab
      if (message_handled == 0x4c7d)
      {
        decodedMsg = handle_autocab(in, 0x4c7d);
      }
      // 0x7d4c Autocab
      if (message_handled == 0x7d4c)
      {
        decodedMsg = handle_autocab(in, 0x7d4c);
      }
      // Auriga
      if (message_handled == 0xeff7)
      {
        decodedMsg = handle_auriga(in);
      }
      // 0xb433 Autocab
      if (message_handled == 0xb433)
      {
        decodedMsg = handle_autocab_e(in);
      }
      // Unknown 0x007e //
      if (message_handled == 0x007e)
      {
        decodedMsg = handle_007e(in, 0x007e);
      }
    }

    if (decodedMsg != null)
    {
      //this.theApp.addArray(decodedMsg, whichChannel);  todo msg decoded
      clear_ready_for_next_msg();
    }
  }

  // Clear assorted variables so the program is ready for the next message //
  public void clear_ready_for_next_msg()
  {
    message_length = 0;
    message_handled = 0;
    bits_rxed = -1;
    preamble_hunt_status = 0;
    if (raw_bits != null)
    {
      raw_bits.clear();
    }
  }
}
