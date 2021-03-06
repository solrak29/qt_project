#include "sigReport.h"
#include <fstream>

void
StigReport::writeAction() {
    RptIteratorType it = actionEntries.begin();
    fstream f;
    f.open("NeedingAction.txt", fstream::out);
    f  << setw(11) << "OLD Status" 
       << setw(26) << "Ruleid OLD/New" 
       << setw(33) << "Vuln OLD/New" 
       << setw(27) << "Stig_id OLD/New\n";
    f  << setfill('-') << setw(110) << "\n"; 
    while( it != actionEntries.end() ){
        f << setw(12) << it->oldStatus;
        f << "    " << setw(15) << it->oldRuleID << "    " << setw(15) << it->newRuleID;
        f << "    " << setw(7) << it->oldVuln << "    " << setw(7) <<  it->newVuln;
        f << "    " << setw(14) << it->oldStig << "    " << setw(14) << it->newStig;
        f << "\n";
        it++;
    }
}

void
StigReport::writeReport() {
    RptIteratorType it = rptEntries.begin();
    fstream f;
    f.open("Report", fstream::out);
    f << "Different Rule_id\n" 
      << setw(11) << "OLD Status" 
      << setw(26) << "Ruleid OLD/New" 
      << setw(33) << "Vuln OLD/New" 
      << setw(27) << "Stig_id OLD/New\n";
    f  << setfill('-') << setw(110) << "\n"; 
    while( it != rptEntries.end() ){
        f << setw(12) << it->oldStatus;
        f << "    " << setw(15) << it->oldRuleID << "    " << setw(15) << it->newRuleID;
        f << "    " << setw(7) << it->oldVuln << "    " << setw(7) <<  it->newVuln;
        f << "    " << setw(14) << it->oldStig << "    " << setw(14) << it->newStig;
        f << "\n";
        it++;
    }
    f << "\n";
    f << "New CKL file count: " << newVulnNumber << " -- Old CLD file count: " << oldVulnNumber << endl; 
    f << "Matching Values: " << matchingValues << endl;
    f << "New Items Added: " << newValues << endl;

    int removed = 0;
    if ( oldVulnNumber > newVulnNumber ) {
        removed = oldVulnNumber - ( newVulnNumber - newValues); 
    } else {
        removed = newVulnNumber - ( oldVulnNumber - newValues); 
    }
    f << "Removed Entries: " << removed << endl;
    f << "Changed Entries: " << changedValues << endl;
    f << "Changed Entries Needed Actions: " << needsAction << endl;
    f.close();
}
