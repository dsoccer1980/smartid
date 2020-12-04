package ru.dsoccer1980.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyRestController {

  //@GetMapping
  public String index() {
    return "Hi";
  }

}
