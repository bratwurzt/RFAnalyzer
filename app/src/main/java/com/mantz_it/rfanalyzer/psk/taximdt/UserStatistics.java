package com.mantz_it.rfanalyzer.psk.taximdt;
// A class for tracking user details

public class UserStatistics
{
  private static int mainIndex;
  private static int mobileIdent[] = new int[4096];
  private static int mobileSystem[] = new int[4096];
  private static int mobileUsageCounter[] = new int[4096];

  // This function is called when the user wants to record activity //
  public void record_activity(int system, int ident)
  {
    int index;
    // See if this user has a record already //
    index = checkIfRecorded(system, ident);
    // If index is -1 then add a new record //
    if (index == -1)
    {
      mobileIdent[mainIndex] = ident;
      mobileSystem[mainIndex] = system;
      mobileUsageCounter[mainIndex] = 1;
      // Increment the index counter //
      mainIndex++;
    }
    else
    {
      // Check if the array will be full //
      if (mainIndex == 4096)
      {
        return;
      }
      // Increment this usage counter //
      mobileUsageCounter[index]++;
    }
  }

  // This function is called to check if a mobile is already recorded //
  // If they are recorded the index is returned else -1 is returned //
  private int checkIfRecorded(int system, int ident)
  {
    int i;
    for (i = 0; i < mainIndex; i++)
    {
      if ((system == mobileSystem[i]) && (ident == mobileIdent[i]))
      {
        return i;
      }
    }
    // Nothing found so return -1 ;
    return -1;
  }

  // This function is called to clear the main index //
  public void clearIndex()
  {
    mainIndex = 0;
  }

  // The function returns a string showing the total number of users //
  public String totalUsers()
  {
    String ret;
    if (mainIndex == 0)
    {
      ret = "No users were logged";
    }
    else
    {
      ret = "A total of ";
      ret = ret + Integer.toString(mainIndex);
      ret = ret + " users were logged";
    }
    return ret;
  }

  // This function returns the a string showing info on a specific user //
  public String lineDetails(int index)
  {
    String ret;
    ret = "Ident : ";
    ret = ret + Integer.toString(mobileIdent[index]);
    ret = ret + " System : ";
    ret = ret + Integer.toString(mobileSystem[index]);
    ret = ret + " (";
    ret = ret + Integer.toString(mobileUsageCounter[index]);
    ret = ret + " messages recorded)";
    return ret;
  }

  // Return the static main index //
  public int GetIndex()
  {
    return mainIndex;
  }

  // Sort the users by mobile ident //
  // This code is standard bubble sort taken from the book
  // "Learning to Program in C" by N.Kantaris //
  public void sortByMobileIdent()
  {
    int i, j, temp, max;
    boolean flag;
    max = mainIndex;
    for (i = 0; i < mainIndex - 1; i++)
    {
      max--;
      flag = false;
      for (j = 0; j < max; j++)
      {
        if (mobileIdent[j] > mobileIdent[j + 1])
        {
          // Mobile ident //
          temp = mobileIdent[j];
          mobileIdent[j] = mobileIdent[j + 1];
          mobileIdent[j + 1] = temp;
          // System //
          temp = mobileSystem[j];
          mobileSystem[j] = mobileSystem[j + 1];
          mobileSystem[j + 1] = temp;
          // Usage Counter //
          temp = mobileUsageCounter[j];
          mobileUsageCounter[j] = mobileUsageCounter[j + 1];
          mobileUsageCounter[j + 1] = temp;
          flag = true;
        }
      }
      if (flag == false)
      {
        break;
      }
    }
  }
}
