package com.mantz_it.rfanalyzer.psk.taximdt;

import java.text.DateFormat;
import java.util.Date;

// A class for measuring channel usage //
public class ChannelStatistics
{
  static public long total_bytes;
  static public int total_good_autocab_packets;
  static public int total_good_auriga_packets;
  static public int total_bad_autocab_packets;
  static public int total_bad_auriga_packets;
  static public long next_snapshot_time;

  // Clear all the objects public variables //
  public void clear()
  {
    Date now = new Date();
    // Set next_snapshot_time to 900 seconds (15 minutes) from this time //
    next_snapshot_time = now.getTime() + (900 * 1000);
    total_bytes = 0;
    total_good_autocab_packets = 0;
    total_good_auriga_packets = 0;
    total_bad_autocab_packets = 0;
    total_bad_auriga_packets = 0;
  }

  // Increment the total_bad_autocab_packets variable //
  public void incBadAutocabPacketsCounter()
  {
    total_bad_autocab_packets++;
  }

  // Increment the total_good_autocab_packets variable //
  public void incGoodAutocabPacketsCounter()
  {
    total_good_autocab_packets++;
  }

  // Add the number of bytes in the message to the total_bytes variable //
  public void addBytesToTotal(int bytes)
  {
    total_bytes = total_bytes + bytes;
  }

  // Increment the total_bad_auriga_packets variable //
  public void incBadAurigaPackets()
  {
    total_bad_auriga_packets++;
  }

  // Increment the total_good_auriga_packets variable //
  public void incGoodAurigaPackets()
  {
    total_good_auriga_packets++;
  }

  // Return the next snapshot time //
  public long getCurrentTime()
  {
    return next_snapshot_time;
  }

  // Create a report line in the format ..
  // Date,Time,Total Packets,
  // Total Good Auriga Packets,Total Bad Auriga Packets,Percentage Bad Auriga
  // Packets,
  // Total Good Autocab Packets,Total Bad Autocab Packets,Percentage Bad
  // Autocab Packets,
  // Total Bytes Transmitted
  public String get_report_line()
  {
    StringBuffer line = new StringBuffer();
    double dtemp, d1, d2;
    int total, total_auriga_packets, total_autocab_packets;

    // Date //
    Date now = new Date();
    DateFormat df = DateFormat.getDateInstance();
    line.append(df.format(now)).append(",");

    // Time //
    DateFormat tdf = DateFormat.getTimeInstance();
    line.append(tdf.format(now)).append(",");

    // Total packets //
    total = total_good_autocab_packets + total_good_auriga_packets
        + total_bad_autocab_packets + total_bad_auriga_packets;
    line.append(total).append(",");

    // Good Auriga Packets //
    line.append(total_good_auriga_packets).append(",");

    // Bad Auriga Packets //
    line.append(total_bad_auriga_packets).append(",");

    // Percentage bad Auriga packets //
    total_auriga_packets = total_good_auriga_packets + total_bad_auriga_packets;
    total_autocab_packets = total_good_autocab_packets + total_bad_autocab_packets;

    d1 = total_bad_auriga_packets;
    d2 = total_auriga_packets;

    if ((d2 == 0.0) && (d1 > 0.0))
    {
      dtemp = 100.0;
    }
    else if ((d2 == 0.0) && (d1 == 0.0))
    {
      dtemp = 0.0;
    }
    else
    {
      dtemp = (d1 / d2) * 100;
    }

    line.append(String.format("%.2f,", dtemp));

    // Good Autocab Packets //
    line.append(total_good_autocab_packets).append(",");

    // Bad Autocab Packets //
    line.append(total_bad_autocab_packets).append(",");

    // Percentage bad Autocab packets //
    d1 = total_bad_autocab_packets;
    d2 = total_autocab_packets;
    if ((d2 == 0.0) && (d1 > 0.0))
    {
      dtemp = 100.0;
    }
    else if ((d2 == 0.0) && (d1 == 0.0))
    {
      dtemp = 0.0;
    }
    else
    {
      dtemp = (d1 / d2) * 100;
    }

    line.append(String.format("%.2f,", dtemp));

    // Total bytes //
    line.append(total_bytes);

    return line.toString();
  }
}