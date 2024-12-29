import CustomRouter from "../../utils/CustomRouter.util.js";
import { readUsers, createUser, updateUser, destroyUser } from "../../controllers/users.controller.js";


class UsersApiRouter extends CustomRouter {
    constructor() {
        super();
        this.init();
    }
    init = () => {
        this.read('/', ['ADMIN'], readUsers);
        this.create('/', ['ADMIN'], createUser);
        this.update('/:id', ['USER', 'ADMIN'], updateUser);
        this.destroy('/:id', ['USER', 'ADMIN'], destroyUser);
    };
}


const usersApiRouter = new UsersApiRouter();
export default usersApiRouter.getRouter();