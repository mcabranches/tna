/*  TNA's FP synthesizer
*   1 - have different files with different FPMs (jinja2 templates)
*   2 - have a main file serving as an XDP entry point
*   3 - Read each file from c code
*   4 - control code generation based on the templates from the c code (call python from c)
*   5 - compile the code
*/
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    boost::property_tree::ptree pt;
    std::stringstream ss;
    std::string pycmd;
    
    //fpm1 is the entry point
    //this dict should also describe fpm specific featues (e.g., vlans, stp)
    pt.put("fpm1", "tnabr");
    //pt.put("tnabr", "tnartr");
    //pt.put("tnartr", "tnaipt");

    boost::property_tree::json_parser::write_json(ss, pt);
    std::cout << ss.str() << std::endl;
    pycmd = "python3 tnasynth.py '" + ss.str() + "'";
    
    system(pycmd.c_str());
    
    return 0;
}


