$(function()
  {
 var validator = $('#login-form').validate(
      {
        rules:
        {
          username: {required:true,
                        },

          password: {required:true,
                        }
        },
        messages:
        {
          username: {required:"Please enter a username", 
                      },        

          password: {required:"Please enter a password", 
                      }        
        },
        errorPlacement: function(error, element) 
        {
            error.insertAfter( element.closest('.wrap-input100') );
         }
      });
    
    $.validator.addMethod(
        "regex",
        function(value, element, regexp) {
            var re = new RegExp(regexp);
            return this.optional(element) || re.test(value);
        },
        "Please check your input."
);
    
    $("#password").rules("add", { regex: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/ })
    
  });