//
// File main.cpp
//
// Main drive of the code that will check for two file names.
// The first argument is the file that will be read to convert to the next file.
// The secon argument is the file that will be created with converted from first file.
//
// Author: carlos.negron.nyc@gmail.com 
//
//
//
//


#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMElement.hpp>
#include <xercesc/dom/DOMText.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/XMLFormatter.hpp>
#include <xercesc/framework/StdOutFormatTarget.hpp>
#include <xercesc/framework/LocalFileFormatTarget.hpp>
//#include <xercesc/util/PlatformUtils.hpp>
#include <iostream>
#include <string>


using namespace std;
using namespace xercesc;

const char* NOT_AVAILABLE_PREV = "STIG Item was not available in previous Release.";
const char* NOT_REVIEWED = "Not_Reviewed";

void usage() {
    cout << "Error Incorrect Arguments" << endl;
    cout << "Usage: xml2sigxml <old filename> < new filename>" << endl;
}

char* getStatus( XMLSize_t index, DOMNodeList* children) {
    DOMElement* e = dynamic_cast< xercesc::DOMElement* >( children->item(index));
    DOMNodeList *data_list = e->getElementsByTagName(XMLString::transcode("FINDING_DETAILS"));
    DOMNode* c = data_list->item(0);
    DOMNode* cc = c->getChildNodes()->item(0);
    DOMText* t = dynamic_cast< xercesc::DOMText* >(cc);
    char* status = XMLString::transcode(t->getWholeText());
    cout << "Found details " << status << endl;
    return status;

}


char* getRuleID( XMLSize_t index, DOMNodeList* children) {
    DOMElement* e = dynamic_cast< xercesc::DOMElement* >( children->item(index));
    DOMNodeList *data_list = e->getElementsByTagName(XMLString::transcode("STIG_DATA"));
    DOMElement* re = dynamic_cast< xercesc::DOMElement* >( data_list->item(3));
    DOMNodeList *att_list = re->getElementsByTagName(XMLString::transcode("ATTRIBUTE_DATA"));
    DOMNode* c = att_list->item(0);
    DOMNode* cc = c->getChildNodes()->item(0);
    DOMText* t = dynamic_cast< xercesc::DOMText* >(cc);
    return XMLString::transcode(t->getWholeText());
}

void checkRuleID( DOMDocument* xmlold, DOMDocument* xmlnew ) {
    DOMElement* xmlnewRoot = xmlnew->getDocumentElement();
    DOMNodeList *children = xmlnewRoot->getElementsByTagName(XMLString::transcode("VULN"));
    const XMLSize_t nodeCount = children->getLength();
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        char* ruleId = getRuleID( i, children);
        
	//
	// Find rule id in old doc
	//
        DOMElement* xmloldRoot = xmlold->getDocumentElement();
        DOMNodeList *children = xmloldRoot->getElementsByTagName(XMLString::transcode("VULN"));
        const XMLSize_t nodeCount = children->getLength();
        for( XMLSize_t i = 0; i < nodeCount; i++ ) {
	    char* oldRuleId = getRuleID( i, children);
	    if (strcmp(ruleId,oldRuleId) == 0 ) {
	        cout << "Found match old " << oldRuleId << " " << ruleId << endl;
		if (strcmp(getStatus(i, children), NOT_REVIEWED) == 0) {
                    cout << "Same rule entries not reviewd" << endl;
		}
		break;
	    }
        }
    }
}

void write_file(DOMDocument* d, const char* filename) {
    DOMLSSerializer* theSerializer = ((DOMImplementationLS*)d->getImplementation())->createLSSerializer();

    // optionally you can set some features on this serializer
    if (theSerializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTDiscardDefaultContent, true))
        theSerializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTDiscardDefaultContent, true);

    if (theSerializer->getDomConfig()->canSetParameter(XMLUni::fgDOMWRTFormatPrettyPrint, true))
        theSerializer->getDomConfig()->setParameter(XMLUni::fgDOMWRTFormatPrettyPrint, true);

    //XMLFormatTarget *myFormTarget = new StdOutFormatTarget();
    XMLFormatTarget *myFormTarget = new LocalFileFormatTarget(XMLString::transcode(filename));
    DOMLSOutput* theOutput = ((DOMImplementationLS*)d->getImplementation())->createLSOutput();
    theOutput->setByteStream(myFormTarget);

    try {
        // do the serialization through DOMLSSerializer::write();
        theSerializer->write(d, theOutput);
    } catch (const XMLException& toCatch) {
            char* message = XMLString::transcode(toCatch.getMessage());
            cout << "Exception message is: \n"
                 << message << "\n";
            XMLString::release(&message);
    }
}

void showValues( DOMNode* node ) {
    if (node->getNodeType() ) {
        switch ( node->getNodeType() ) {
            case DOMNode::ELEMENT_NODE:
            {
                DOMElement* currentElement = dynamic_cast< xercesc::DOMElement* >( node );
                cout << XMLString::transcode(currentElement->getTagName()) << endl;
                break;
            }
            case DOMNode::TEXT_NODE:
            {
                DOMText* currentText = dynamic_cast< xercesc::DOMText* >( node );
                cout << XMLString::transcode(currentText->getWholeText()) << endl;
                break;
            }
            default:
                cout << "Found node type " << node->getNodeType() << endl;
                    
         };
    } else {
        cout << "No node type returned" << endl;
    }

}

void check_fill_in_statements(DOMDocument* d, const char* elements) {
    cout << "Testing Filling in statements" << endl;
    DOMElement* root = d->getDocumentElement();
    DOMNodeList *children = root->getElementsByTagName(XMLString::transcode(elements));
    const XMLSize_t nodeCount = children->getLength();
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        DOMNode* node = children->item(i);
        showValues(node); 
        // if there is child it will be a text value otherwise we add child with the text value above.
        if (node->hasChildNodes()) {
            DOMNodeList *children = node->getChildNodes();
            DOMNode* child = children->item(0);
            DOMText* currentText = dynamic_cast< xercesc::DOMText* >( child );
            cout << XMLString::transcode(currentText->getWholeText()) << endl;
        } else {
            cout << "nothing changed test failed" << endl;
        }
    }

}
//
//  Fill in the statments for FINDING_DETAILS and COMMENTS 
//
void fill_in_statements(DOMDocument* d , const char* elements, const char* value) {
    cout << "Filling in statements" << endl;
    DOMElement* root = d->getDocumentElement();
    DOMNodeList *children = root->getElementsByTagName(XMLString::transcode(elements));
    const XMLSize_t nodeCount = children->getLength();
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        DOMNode* node = children->item(i);
        showValues(node); 
        // if there is child it will be a text value otherwise we add child with the text value above.
        if (node->hasChildNodes()) {
            DOMNodeList *children = node->getChildNodes();
            DOMNode* child = children->item(0);
            DOMText* currentText = dynamic_cast< xercesc::DOMText* >( child );
            cout << XMLString::transcode(currentText->getWholeText()) << endl;
            cout << "changing to..." << endl;
            cout << value << endl;
            currentText->replaceWholeText(XMLString::transcode(value));
        } else {
            cout << "adding to..." << endl;
            node->appendChild( d->createTextNode(XMLString::transcode(value)));
        }
    }

}

void traverse( DOMDocument* d ) {
    cout << "Traversing statements" << endl;
    DOMElement* root = d->getDocumentElement();
    cout << "Root Element " << XMLString::transcode(root->getTagName()) << endl;
    DOMNodeList *children = root->getChildNodes();
    const XMLSize_t nodeCount = children->getLength();
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        showValues(children->item(i));
    }
}

void processFiles(const string& fileIn, const string& fileOut) {
    try {
        XMLPlatformUtils::Initialize();
    } catch (const XMLException& toCatch ) {
        cerr << "exception caught" << endl;
    }
    XercesDOMParser* parserOldFile = new XercesDOMParser();
    parserOldFile->setValidationScheme( XercesDOMParser::Val_Never );
    parserOldFile->setDoNamespaces(false);
    parserOldFile->setDoSchema(false);
    parserOldFile->setLoadExternalDTD(false);
    XercesDOMParser* parserNewFile = new XercesDOMParser();
    parserNewFile->setValidationScheme( XercesDOMParser::Val_Never );
    parserNewFile->setDoNamespaces(false);
    parserNewFile->setDoSchema(false);
    parserNewFile->setLoadExternalDTD(false);
    try {
        parserOldFile->parse(fileIn.c_str());
        parserNewFile->parse(fileOut.c_str());
        DOMDocument* docOldFile = parserOldFile->getDocument();
        DOMDocument* docNewFile = parserNewFile->getDocument();
        // Update fields with new values
        fill_in_statements(docNewFile, "FINDING_DETAILS", NOT_AVAILABLE_PREV ); 
        check_fill_in_statements(docNewFile, "FINDING_DETAILS" ); 
        fill_in_statements(docNewFile, "COMMENTS", NOT_AVAILABLE_PREV ); 
        check_fill_in_statements(docNewFile, "COMMENTS" ); 
        // Compare rule_id changes on old to new
        checkRuleID( docOldFile, docNewFile );
        //write_file(docNewFile, "test");
    } catch ( const XMLException& toCatch ) {
        cerr << "exception caught in parsing" << endl;
    }
    XMLPlatformUtils::Terminate();
}

int main(int argc, char** argv ) {
    // keep it simple and just see that we have the right args
    if (argc > 2 ) {
    string fileIn = argv[1];
    string fileOut = argv[2];
    cout << "Processing old file => " << fileIn << endl;
    cout << "Processing new file => " << fileOut << endl;
    processFiles(fileIn, fileOut);
    cout << "finished" << endl;
    } else {
        usage();
    }
    return 0;
}
