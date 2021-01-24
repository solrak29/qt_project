#ifndef __SIG_REPORT__H__
#define __SIG_REPORT__H__
#include <string>
#include <vector>
#include <iomanip>
#include <iostream>

using namespace std;


class StigReport {
     public: 
    struct reportRecord {
    string oldStatus;
    string oldRuleID;
    string newRuleID;
    string oldVuln;
    string newVuln;
    string oldStig;
    string newStig;
    };
    typedef vector<reportRecord> RptListType;
    typedef vector<reportRecord>::iterator RptIteratorType;
         StigReport(){};
         ~StigReport(){};
         void addToReport(const reportRecord& rec){ rptEntries.push_back(rec);};
         void addToAction(const reportRecord& rec){ actionEntries.push_back(rec);};
         void writeReport();
         void writeAction();
         void addOldVuln( int vuln ) {oldVulnNumber = vuln;};
         void addNewVuln( int vuln ) {newVulnNumber = vuln;};
         void addMatching( int match) {matchingValues = match;};
         void addNew( int newVal ) {newValues = newVal;};
         void addChanged( int val ) {changedValues = val;};
         void addNeedsAction(int val ) {needsAction = val;};
     private:
        int oldVulnNumber;
        int newVulnNumber;
        int matchingValues;
        int newValues;
        int changedValues;
        int needsAction;
        RptListType rptEntries;
        RptListType actionEntries;
};
#endif
