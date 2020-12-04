package ru.dsoccer1980.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;

@Controller
public class MainController {

  @GetMapping(value = "/my")
  public String index(Model model) {
    return "index";
  }

  @ModelAttribute("first_name")
  public String addToModel() {
    return "Sasha";
  }

  @GetMapping(value = "/smart")
  public String smartid() {
    return "smartId";
  }

}
