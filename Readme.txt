Основные сущности модуля
Модуль представлен двумя сущностями: User и Role
Класс User реализует класс UserDetails, который предоставляет необходимую информацию для построения объекта Authentication из DAO объектов приложения или других источников данных системы безопасности. Объект UserDetailsсодержит имя пользователя, пароль, флаги: isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled и Collection — прав (ролей) пользователя.

@Entity
@Table(name = "t_user")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Size(min=5, message = "Не меньше 5 знаков")
    private String username;
    @Size(min=5, message = "Не меньше 5 знаков")
    private String password;
    @Transient
    private String passwordConfirm;
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;

    public User(){
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }

    @Override
    public String getUsername() {
        return username;
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
@Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getRoles();
    }
    @Override
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    public String getPasswordConfirm() {
        return passwordConfirm;
    }
    public void setPasswordConfirm(String passwordConfirm) {
        this.passwordConfirm = passwordConfirm;
    }
    public Set<Role> getRoles() {
        return roles;
    }
    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}

Класс User реализует класс GrantedAuthority, который отражает разрешения, выданные пользователю в масштабе всего приложения, такие разрешения (как правило называются «роли»), например ROLE_ANONYMOUS, ROLE_USER, ROLE_ADMIN. В нашем случае роли с пользователями связаны отношением многие-ко-многим.



@Entity
@Table(name = "t_role")
public class Role implements GrantedAuthority {
    @Id
    private Long id;
    private String name;
    @Transient
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;
    public Role() {
    }

    public Role(Long id) {
        this.id = id;
    }

    public Role(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<User> getUsers() {
        return users;
    }

    public void setUsers(Set<User> users) {
        this.users = users;
    }

    @Override
    public String getAuthority() {
        return getName();
    }
}
3.3.2 Хранение данных
Хранение данных организовано в БД PostgreSQL. Используем интерфейсы, расширяющие JPAReposytory, который в свою очередь наследуется от CrudRepository. 
CrudRepository является базовым интерфейсом в Spring Data, который предоставляет базовые методы CRUD. 
JpaRepository, с другой стороны, предоставляет дополнительные функции, специфичные для JPA, такие как flush(), deleteInBatch(), deleteAllInBatch(), и т.д.
При этом в UserRepository мы описываем метод, возвращающий пользователя по его имени.

public interface RoleRepository extends JpaRepository<Role, Long> {}


public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}


	
3.3.3 Сервис
Сервисный слой представлен классом UserService, реализующим интерфейс UserDetailService, который используется, чтобы создать UserDetails объект путем реализации единственного метода этого интерфейса.
@Service
public class UserService implements UserDetailsService {
    @PersistenceContext
    private EntityManager em;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;



    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        return user;
    }
    public User findUserById(Long userId) {
        Optional<User> userFromDb = userRepository.findById(userId);
        return userFromDb.orElse(new User());
    }
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    public List<User> allUsers() {
        return userRepository.findAll();
    }
    public boolean saveUser(User user) {
	User userFromDB = userRepository.findByUsername(user.getUsername());
        if (userFromDB != null) {
            return false;
        }
        if (userRepository.count() == 0){
            user.setRoles(new HashSet<Role>(Arrays.asList(
                    new Role(1L, "ROLE_ADMIN"),
                    new Role(2L, "ROLE_USER"))));
        }
        else {
            user.setRoles(Collections.singleton(new Role(2L, "ROLE_USER")));
        }
        roleRepository.saveAll(user.getRoles());
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }

    public boolean deleteUser(Long userId) {
        if (userRepository.findById(userId).isPresent()
                && !userRepository.findById(userId).get().getRoles()
		.stream().anyMatch(role -> role.getName().equals("ROLE_ADMIN"))) {
            userRepository.deleteById(userId);
            return true;
        }
        return false;
    }

    public List<User> usergtList(Long idMin) {
    return em.createQuery("SELECT u FROM User u WHERE u.id > :paramId", User.class)
                .setParameter("paramId", idMin).getResultList();
    }
}
3.3.4 Контроллеры 
Контроллеры представлены двумя контроллерами RegistrationController и AdminController. 
RegistrationController  отвечает за регистрацию нового пользователя в системе. При этом первый зарегистрированный пользователь получает роль ADMIN и может удалять других пользователей. Себя при этом он удалить не может. Все последующие пользователи получают роль USER и имеют более ограниченные права. Планируется в дальнейшем расширить используемые роли и больше разделить права доступа.


@Controller
public class RegistrationController {

    @Autowired
    private UserService userService;

    @GetMapping("/registration")
    public String registration(Model model) {
        model.addAttribute("userForm", new User());

        return "registration";
    }

    @PostMapping("/registration")
    public String addUser(@ModelAttribute("userForm") @Valid User userForm, 
BindingResult bindingResult, Model model) {

        if (bindingResult.hasErrors()) {
            return "registration";
        }
        if (!userForm.getPassword().equals(userForm.getPasswordConfirm())){
            model.addAttribute("passwordError", "Пароли не совпадают");
            return "registration";
        }
        if (!userService.saveUser(userForm)){
            model.addAttribute("usernameError", "Пользователь с таким именем уже существует");
            return "registration";
        }

        return "redirect:/";
    }
}




AdminController отвечает за управление учетными данными пользователя в системе. Доступ к ветке разрешен пользователю с правами ADMIN. Администратор может удалить любого пользователя, кроме себя.


@Controller
public class AdminController {
    @Autowired
    private UserService userService;

    @GetMapping("/admin")
    public String userList(Model model) {
        model.addAttribute("allUsers", userService.allUsers());
        return "admin";
    }

    @PostMapping("/admin")
    public String  deleteUser(@RequestParam(required = true, defaultValue = "" ) Long userId, @RequestParam(required = true, defaultValue = "" ) String action, Model model) {
        if (action.equals("delete")){
            userService.deleteUser(userId);
        }
        return "redirect:/admin";
    }

    @GetMapping("/admin/gt/{userId}")
    public String  gtUser(@PathVariable("userId") Long userId, Model model) {
        model.addAttribute("allUsers", userService.usergtList(userId));
        return "admin";
    }
}
3.3.5 Настройки безопасности
Настройки безопасности пока представлены классом WebSecurityConfig расширающим WebSecurityConfigurerAdapter. Понимаю, что такой подход сейчас устарел и требует замены на современные, но в попытках написать что-то актуальное и стоящее провел много времени и пока это единственный вариант, который удалось довести до корректного запуска и работы.


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
          return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                    .disable()
                .authorizeRequests()
                    //Доступ только для не зарегистрированных пользователей
                    //.antMatchers("/registration").not().fullyAuthenticated()
                    //Доступ только для пользователей с ролью Администратор
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/devices").hasRole("USER")
                    //Доступ разрешен всем пользователей
                    .antMatchers("/", "/resources/**", "/registration").permitAll()
                //Все остальные страницы требуют аутентификации
                .anyRequest().authenticated()
                .and()
                    //Настройка для входа в систему
                    .formLogin()
                    .loginPage("/login")
                    //Перенарпавление на главную страницу после успешного входа
                    .defaultSuccessUrl("/")
                    .permitAll()
                .and()
                    .logout()
                    .permitAll()
                    .logoutSuccessUrl("/");
    }

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }
}
3.3.6 Веб-приложение для работы с модулем
Для проверки работы модуля пока организовал несколько страниц. На страницах организована чистая функциональность, без приукрашательств. Организован переход между страницами, перенаправление в зависимости от успешности регистрации и авторизации. Организована логика взаимодействия с пользователем. Обработаны некоторые ошибки.
Стартовая страница 
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8" %>

<!DOCTYPE HTML>
<html>
<head>
  <title>Главная</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <link rel="stylesheet" type="text/css" href="${contextPath}/resources/css/style.css">
</head>
<body>
<div>
  <sec:authorize access="!isAuthenticated()">
    <h3>Пользователь не авторизован</h3>
    <h4><a href="/login">Войти</a></h4>
  </sec:authorize>
  <sec:authorize access="isAuthenticated()">
    <h3>Авторизован пользователь: ${pageContext.request.userPrincipal.name}</h3>
    <h4><a href="/logout">Выйти</a></h4>
  </sec:authorize>
  <h4><a href="/registration">Зарегистрировать нового пользователя</a></h4>
  <h4><a href="/devices">Приборы (только зарегистрированные пользователи)</a></h4>
  <h4><a href="/admin">Пользователи (только админ)</a></h4>
</div>
</body>
</html>

Страница авторизации
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8" %>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Log in with your account</title>
</head>

<body>
<sec:authorize access="isAuthenticated()">
  <% response.sendRedirect("/"); %>
</sec:authorize>
<div>
  <form method="POST" action="/login">
    <h2>Вход в систему</h2>
    <div>
      <input name="username" type="text" placeholder="Username"
             autofocus="true"/>
      <input name="password" type="password" placeholder="Password"/>
      <button type="submit">Log In</button>
      <h4><a href="/registration">Зарегистрироваться</a></h4>
    </div>
  </form>
</div>
</body>
</html>

Страница регистрации нового пользователя
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8" %>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Регистрация</title>
</head>
<body>
<div>
  <form:form method="POST" modelAttribute="userForm">
    <h2>Регистрация</h2>
    <div>
      <form:input type="text" path="username" placeholder="Username"
                  autofocus="true"></form:input>
      <form:errors path="username"></form:errors>
        ${usernameError}
    </div>
    <div>
      <form:input type="password" path="password" placeholder="Password"></form:input>
    </div>
    <div>
      <form:input type="password" path="passwordConfirm"
                  placeholder="Confirm your password"></form:input>
      <form:errors path="password"></form:errors>
        ${passwordError}
    </div>
    <button type="submit">Зарегистрироваться</button>
  </form:form>
  <a href="/">Главная</a>
</div>
</body>
</html>

Страница администрирования учетных записей
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8" %>

<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Log in with your account</title>
  <link rel="stylesheet" type="text/css" href="${contextPath}/resources/css/style.css">
</head>

<body>
<div>
  <table>
    <thead>
    <th>ID</th>
    <th>UserName</th>
    <th>Password</th>
    <th>Roles</th>
    </thead>
    <c:forEach items="${allUsers}" var="user">
      <tr>
        <td>${user.id}</td>
        <td>${user.username}</td>
        <td>${user.password}</td>
        <td>
          <c:forEach items="${user.roles}" var="role">${role.name}; </c:forEach>
        </td>
        <td>
          <form action="${pageContext.request.contextPath}/admin" method="post">
            <input type="hidden" name="userId" value="${user.id}"/>
            <input type="hidden" name="action" value="delete"/>
            <button type="submit">Delete</button>
          </form>

        </td>

      </tr>
    </c:forEach>
  </table>
  <a href="/">Главная</a>
</div>
</body>
</html>







3.3.7 Общие параметры запуска
Для запуска приложения используются следующие настройки описанные в application.properties
spring.datasource.url=jdbc:postgresql://localhost:5432/HeatDB
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.jpa.show-sql=true
spring.jpa.generate-ddl=false
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true

spring.mvc.view.prefix = /WEB-INF/jsp/
spring.mvc.view.suffix = .jsp

База данных развернута в контейнере Docker и запускается через .bat файл
docker-compose.exe up -d

Настройки запуска прописаны в docker-compose.yml
version: '3'
services:
  postgres:
    image: postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_USER=postgres
      - POSTGRES_DB=HeatDB
    volumes:
      - ./database:/var/lib/postgresql/data


3.4 Модуль сбора и регистрации данных с приборов 
Данные с приборов можно разделить на две большие группы: 
- данные настройки и конфигурации прибора;
- часовые и суточные данные учета тепла.
Приборы являются сложными устройствами, способными вести учет тепловой энергии сразу в двух системах, используя для вычислений до 7 датчиков температуры, до 6 датчиков давления, до 6 датчиков расхода. При этом каждый из подключенных датчиков конфигурируется в приборе несколькими параметрами. 
Часовые и суточные данные также представлены множеством значений, в зависимости от режима работы прибора (штатный, с ошибкой/ами по каналам датчиков, с отключенным электропитанием и т.д.) При этом накопление данных в постоянной памяти ведется в течение 5-ти лет, а хранение после отключения – в течение 10-ти.
3.4.1 Основные сущности модуля
Проработка архитектуры и формата хранения еще на этапе проектирования, поэтому классы прибора и часовых данных заменены на классы-заглушки.
Модуль представлен двумя сущностями: Device и Data. 




@Entity
@Table(name = "t_devices")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "ID", updatable = false, nullable = false)
    private Long id = null;

    @Column(name = "number")
    private String number;

    @Column(name = "name", nullable = false)
    private String name;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonBackReference
    private User user;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "device", fetch = FetchType.LAZY, 
orphanRemoval = true)
    @JsonManagedReference
    private Set<Data> data = new HashSet<>();

    public void setDeviceData(Set<Data> data) {
        this.data.clear();
        if (data != null) {
            this.data.addAll(data);
        }
    }
}




@Entity
@Table(name = "t_data")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class Data implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id = null;

    @Column(name = "data", updatable = false, nullable = false)
    private String data = null;


    @ManyToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    private Device device;
}


3.4.2 Хранение данных
Хранение данных организовано в БД PostgreSQL. Используем интерфейсы, расширяющие JPAReposytory.
public interface DeviceRepository extends JpaRepository<Device, Long> {
    List<Device> findAllByUser(User user);
    Device findByNumber(String number);
}


public interface DataRepository extends JpaRepository<Data, Long> {
}


3.4.3 Сервис
Сервисный слой представлен интерфейсом DeviceService и классом DeviceServiceImpl его реализующим. 
Интерфейс DeviceService введен для создания архитектурной границы.


public interface DeviceService {
    Device get(Long id);
    Device get(String number);
    List<Device> getAll();
    List<Device> findAllByUser(User user);
    void create(Device device);
}
	
Пока реализовано добавление прибора пользователем, отображение всех приборов пользователя, отображение конкретного прибора по номеру.




@Service
public class DeviceServiceImpl implements DeviceService{
    private DeviceRepository deviceRepository;

    private DataRepository dataRepository;

    public DeviceServiceImpl(DataRepository dataRepository, DeviceRepository deviceRepository) {
        this.dataRepository = dataRepository;
        this.deviceRepository = deviceRepository;
    }

    @Override
    public Device get(Long id) {
        return null;
    }

    @Override
    public Device get(String number) {
        return deviceRepository.findByNumber(number);
    }

    @Override
    public List<Device> getAll() {
        return null;
    }
    @Override
    public List<Device> findAllByUser(User user){
        return deviceRepository.findAllByUser(user);
    }

    @Override
    public void create(Device device) {
        deviceRepository.save(device);
        System.out.println(device);
    }
}



3.4.4 Контроллеры 
Контроллер представлен пока одним контроллером DeviceController. 
DeviceController  отвечает за регистрацию нового устройства в системе, выдачу информации по конкретному устройству, выдачу всех устройств пользователя.
Данный контроллер организован как REST-контроллер, возвращающий данные в формате JSON.
Контролер работает пока сразу с двумя сервисами, и сервисом устройств, и сервисом пользователей. В дальнейшем планируется выделить работу с устройствами в отдельный микросервис.
@RestController
@RequestMapping("/devices")
public class DeviceController {

    private DeviceService deviceService;
    private UserService userService;

    public DeviceController(DeviceService deviceService, UserService userService) {
        this.deviceService = deviceService;
        this.userService = userService;
    }

    @GetMapping()
    public List<Device> getDevices(Principal principal) {
        return deviceService.findAllByUser(userService.findUserByUsername(principal.getName()));
    }

  


  @RequestMapping(value = "/{deviceNumber}", method = RequestMethod.GET, 
produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.OK)
    public @ResponseBody
    Device get(@PathVariable String deviceNumber) {
        return deviceService.get(deviceNumber);
    }
    @RequestMapping(value = "/", method = RequestMethod.POST, 
produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.OK)
    public ResponseEntity<?> create(Principal principal, @RequestBody Device device) {
        device.setUser(userService.findUserByUsername("admin"));
        deviceService.create(device);
        HttpHeaders headers = new HttpHeaders();
        ControllerLinkBuilder linkBuilder = linkTo(methodOn(DeviceController.class).get(device.getNumber()));
        headers.setLocation(linkBuilder.toUri());
        return new ResponseEntity<>(headers, HttpStatus.CREATED);
    }
}
3.4.5 Настройки безопасности
Настройки безопасности пока представлены классом WebSecurityConfig расширающим WebSecurityConfigurerAdapter. Доступ к ветке /devices разрешен, авторизованным пользователям с ролью USER. 


@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
          return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                    .disable()
                .authorizeRequests()
                    //Доступ только для пользователей с ролью Администратор
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/devices").hasRole("USER")
                    //Доступ разрешен всем пользователей
                    .antMatchers("/", "/resources/**", "/registration").permitAll()
                //Все остальные страницы требуют аутентификации
                .anyRequest().authenticated()
                .and()
                    //Настройка для входа в систему
                    .formLogin()
                    .loginPage("/login")
                    //Перенарпавление на главную страницу после успешного входа
                    .defaultSuccessUrl("/")
                    .permitAll()
                .and()
                    .logout()
                    .permitAll()
                    .logoutSuccessUrl("/");
    }

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }
}
3.4.6 Веб-приложение для работы с модулем
Веб-часть доступа к модулю еще только проектируется. Возможно, сервис так и останется в виде REST-сервиса, для принятия, хранения и предоставления данных об устройствах, а визуальная часть будет предусмотрена в сервисе предоставления отчетов.
3.4.7 Общие параметры запуска
Для запуска модуля пока используются совместные с модулем пользователей настройки приложения описанные в application.properties.
spring.datasource.url=jdbc:postgresql://localhost:5432/HeatDB
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.jpa.show-sql=true
spring.jpa.generate-ddl=false
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true

spring.mvc.view.prefix = /WEB-INF/jsp/
spring.mvc.view.suffix = .jsp

Таблицы базы данных в БД пользователей. БД развернута в контейнере Docker и запускается через .bat файл
docker-compose.exe up -d

Настройки запуска прописаны в docker-compose.yml
version: '3'
services:
  postgres:
    image: postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_USER=postgres
      - POSTGRES_DB=HeatDB
    volumes:
      - ./database:/var/lib/postgresql/data