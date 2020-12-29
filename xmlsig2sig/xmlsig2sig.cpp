//
// File xmlsig2sig.cpp
//
//  Processing of xml files
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
#include "stigconst.h"


using namespace std;
using namespace xercesc;


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

char* getAttr( const char* attrib, DOMNodeList* data_list, XMLSize_t index ) {
    // Get the element object for the currenc STIG_DATA
    DOMElement* re = dynamic_cast< xercesc::DOMElement* >( data_list->item(index));
    // Get all elements that this attribute name (should only be one)
    DOMNodeList *att_list = re->getElementsByTagName(XMLString::transcode(attrib));
    //cout << "Recieved " << att_list->getLength() << " for " << attrib << endl;
    // Get this node
    DOMNode* c = att_list->item(0);
    // Get this chiled which witll be the text
    //cout << "Number of children here are " << c->getChildNodes()->getLength() << endl;
    DOMNode* cc = c->getChildNodes()->item(0);
    // extract the text from the node.
    DOMText* t = dynamic_cast< xercesc::DOMText* >(cc);
    //cout << "Value here is " << XMLString::transcode(t->getWholeText()) << ":" << endl;

    return XMLString::transcode(t->getWholeText());
}

char* getVulnAttr( const char* attr, XMLSize_t index, DOMNodeList* children) {
    cout << "Getting Vulnerability Attribute " << attr << "..." << endl;
    // Get this VULN element object
    DOMElement* e = dynamic_cast< xercesc::DOMElement* >( children->item(index));
    // Get all the STIG_DATA elements 
    DOMNodeList *data_list = e->getElementsByTagName(XMLString::transcode(STIG_DATA));
    const XMLSize_t nodeCount = data_list->getLength();
    //cout << "Found " << nodeCount << " STIG DATA for Vulnerability" << endl;
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        // does this stig data have our attr we are looking for?
        int len = strlen(getAttr(VULN_ATTRIB, data_list, i));
        char* val = getAttr(VULN_ATTRIB, data_list, i);
        if ( strncmp(val, attr, (strlen(attr)-1)) == 0 ){
            // now the value that should be there
            return getAttr(ATTRIB_DATA, data_list, i);
        }
    }
    cout << "No attribute found..." << endl;
    return "None";
}

// Iterate through all the vulnerablitlies of the new file.
// Find the (rule_id, vulnerabiliity number, and stig id).
void checkRuleID( DOMDocument* xmlold, DOMDocument* xmlnew ) {
    cout << "Checking for rule changes..." << endl;
    DOMElement* xmlnewRoot = xmlnew->getDocumentElement();
    //
    // get all the childrent element under VULN tag
    //
    DOMNodeList *children = xmlnewRoot->getElementsByTagName(XMLString::transcode("VULN"));
    const XMLSize_t nodeCount = children->getLength();
    //cout << "Found " << nodeCount << " Vulneralability Elements" << endl;
    for( XMLSize_t i = 0; i < nodeCount; i++ ) {
        // Get the three elements under the VULN TAG
        char* ruleId = getVulnAttr( RULEID, i, children);
        char* vulnNum = getVulnAttr( VULNNUM, i, children);
        char* stigId = getVulnAttr( STIGID, i, children);
        cout << "Found rule id " << ruleId << endl;
        cout << "Found vule num " << vulnNum << endl;
        cout << "Found stigid " << stigId << endl;
        
	    //
	    // Find rule id in old doc
	    /*
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
        */
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
#ifdef DEBUG
        showValues(node); 
#endif
        // if there is child it will be a text value otherwise we add child with the text value above.
        if (node->hasChildNodes()) {
            DOMNodeList *children = node->getChildNodes();
            DOMNode* child = children->item(0);
            DOMText* currentText = dynamic_cast< xercesc::DOMText* >( child );
#ifdef DEBUG
            cout << XMLString::transcode(currentText->getWholeText()) << endl;
#endif
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
#ifdef DEBUG
        showValues(node); 
#endif
        // if there is child it will be a text value otherwise we add child with the text value above.
        if (node->hasChildNodes()) {
            DOMNodeList *children = node->getChildNodes();
            DOMNode* child = children->item(0);
            DOMText* currentText = dynamic_cast< xercesc::DOMText* >( child );
#ifdef DEBUG
            cout << XMLString::transcode(currentText->getWholeText()) << endl;
            cout << "changing to..." << endl;
            cout << value << endl;
#endif
            currentText->replaceWholeText(XMLString::transcode(value));
        } else {
#ifdef DEBUG
            cout << "adding to..." << endl;
#endif
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

DOMDocument* loadXmlFile( const string& file, XercesDOMParser* xmlDom) {

    DOMDocument* doc = NULL;

    if (xmlDom) {
        xmlDom->setValidationScheme( XercesDOMParser::Val_Never );
        xmlDom->setDoNamespaces(false);
        xmlDom->setDoSchema(false);
        xmlDom->setLoadExternalDTD(false);
        try {
            xmlDom->parse(file.c_str());
            doc = xmlDom->getDocument();
        } catch ( const XMLException& toCatch ) {
            cerr << "exception caught in parsing" << endl;
        }

    } else {
        cerr << "Xml Dom Not Instantiated" << endl;
    }

    return doc;

}

void processFiles(const string& fileOld, const string& fileNew) {
    try {
        XMLPlatformUtils::Initialize();
        XercesDOMParser* xmlOld = new XercesDOMParser();
        XercesDOMParser* xmlNew = new XercesDOMParser();
        DOMDocument* docOld = loadXmlFile( fileOld, xmlOld);
        DOMDocument* docNew = loadXmlFile( fileNew, xmlNew);
        // Update fields with new values
        fill_in_statements(docNew, "FINDING_DETAILS", NOT_AVAILABLE_PREV ); 
        check_fill_in_statements(docNew, "FINDING_DETAILS" ); 
        fill_in_statements(docNew, "COMMENTS", NOT_AVAILABLE_PREV ); 
        check_fill_in_statements(docNew, "COMMENTS" ); 
        // Compare rule_id changes on old to new
        checkRuleID( docOld, docNew );
        //write_file(docNewFile, "test");
        XMLPlatformUtils::Terminate();
    } catch (const XMLException& toCatch ) {
        cerr << "exception caught on initialization" << endl;
    }
}

